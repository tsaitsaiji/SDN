# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib.packet import ether_types
import time,math
from ryu.lib.packet import ethernet, ipv4, tcp
from collections import OrderedDict
import csv
import os
from datetime import datetime
import numpy as np
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.syn_count = 0 #add SYN counter
        self.last_time = time.time()
        self.drop_added = False
        self.first_syn_ack_received=False
        self.ack_from_h1_received = False  
        self.ack_log_printed = False
        self.warning_displayed = False
        self.syn_ack_count=0
        self.hoc_count=0
        self.last_syn_ack_timestamp = {}
        self.hoc_incremented = {}
        self.flow_src_ip = None
        self.flow_src_ip = None
        self.flow_src_port = None
        self.flow_dst_ip = None
        self.flow_dst_port = None
        self.T1=15
        self.T2=2
        self.K=1.5
        self.N=500
        self.hard_time_out =15
        self.M1=7500
        self.M2=7000
        self.src_ip=None
        self.dst_ip=None
        self.src_port=None
        self.dst_port=None
        self.src_mac=None
        self.dst_mac=None
        self.src_in_port=None
        self.dst_in_port=None
        self.ip_to_port = OrderedDict()
        self.in_port_list=[]
        self.ip_list=[]
        self.SN_list=[]
        self.AN=None
        self.SN=None
        self.last_list_clear_time = time.time()
        self.src_3_port=None
        self.src_3_ip=None
        self.dst_3_port=None
        self.dst_3_ip=None
        self.total_ack_packet_count=0
        self
        self.datapth_s1=None
        self.datapath_s2=None
        self.datapath_s3=None
        self.datapath_s4=None
        self.datapath_s5=None
        self.random=0
        self.s2=0
        self.s3=0
        self.s1=0
        self.start_time = time.time()
        self.ack_packet_count=0
        self.ack_packet=[]
        self.switch_out_port=None
    def in_and_out(self, datapath,in_port,out_port,priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=in_port
                )
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            priority=priority,
            instructions=inst
        )

        # Send the flow table entry to the switch
        datapath.send_msg(mod)


    def in_and_out_controller(self, datapath, in_port,out_port, priority):
        # Get the OpenFlow protocol and parser for the current datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct a match for incoming packets on the specified in_port
        match = parser.OFPMatch(in_port=in_port)

        # Define the action to send the packet to the controller
        action = parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)

        # Create an instruction to apply the defined action
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [action])]

        # Construct the FlowMod message to add the flow entry
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                priority=priority,
                                instructions=instructions)

        # Send the FlowMod message to the switch
        datapath.send_msg(mod)

    def select_route_syn(self, datapath, group_id):
            # Retrieve OpenFlow protocol and parser
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Define match criteria for TCP SYN packets
        match = parser.OFPMatch()

        # Define actions to output packets to specific ports
        actions = [parser.OFPActionOutput(2), parser.OFPActionOutput(3), parser.OFPActionOutput(4)]

        # Define instructions to apply the actions
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Construct FlowMod message to install the flow entry for TCP SYN packets
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1,
            match=match,
            instructions=instructions
        )

        # Send the FlowMod message to the switch
        datapath.send_msg(flow_mod)

        # Define buckets for the group, each containing an action
        buckets = [parser.OFPBucket(actions=actions)]

        # Construct GroupMod message to add the group entry
        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                ofproto.OFPGT_SELECT, group_id, buckets)

        # Send the GroupMod message to the switch
        datapath.send_msg(req)
        

        #self.logger.info("Added select_route_syn flow entry for group_id=%s", group_id)

        # Define buckets for the group with weights (for example, 1:2:2)
        buckets = [
            parser.OFPBucket(weight=100, actions=[parser.OFPActionOutput(2)]),
            parser.OFPBucket(weight=100, actions=[parser.OFPActionOutput(3)]),
            parser.OFPBucket(weight=100, actions=[parser.OFPActionOutput(4)])
            ]
        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                ofproto.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)
    def select_route_ack(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=0x10) #syn
        actions = [parser.OFPActionOutput(2), parser.OFPActionOutput(3), parser.OFPActionOutput(4)]
        buckets = [parser.OFPBucket(actions=actions)]
        mod = parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD,
                          ofproto.OFPGT_SELECT, 1, buckets,match=match)
        datapath.send_msg(mod)

    def use_group(self, datapath, in_port, group_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        match = parser.OFPMatch(in_port=in_port)


        actions = [parser.OFPActionGroup(group_id)]


        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]


        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            cookie=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            priority=1,  
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,
            instructions=instructions
        )


        datapath.send_msg(flow_mod)
    @staticmethod
    def dst_ip_dst_port_s2(datapath,ip_dst,priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(ipv4_dst=ip_dst, tcp_dst=1235)

        actions = [parser.OFPActionOutput(1)]


        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]


        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,  
            match=match,
            instructions=instructions,
            command=ofproto.OFPFC_ADD, 
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,
        )
        datapath.send_msg(flow_mod)

    @staticmethod
    def syn_ack_s2(datapath,ip_dst,port_dst,out_port,hard_time_out,priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(ipv4_dst=ip_dst, tcp_dst=port_dst)


        actions = [parser.OFPActionOutput(out_port)]

        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            command=ofproto.OFPFC_ADD, 
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,
            hard_timeout=hard_time_out
        )
        datapath.send_msg(flow_mod)


    @staticmethod   
    def ack_s1(datapath, ip_src, dst_port, dst_ip, src_port, out_port, priority, hard_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(ipv4_src=ip_src, tcp_src=src_port, tcp_flags=0x10, tcp_dst=dst_port, ipv4_dst=dst_ip)

        actions = [parser.OFPActionOutput(out_port)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            priority=priority,
            instructions=inst,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(flow_mod)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #self.logger.info("Switch connected: datapath ID = %016x, address = %s, datapath= %s", datapath.id, datapath.address,datapath)
        if datapath.id == 1:
                self.logger.info("Received PacketIn from s1")
                self.datapth_s1=datapath
                self.logger.info("s1 datapath %s",datapath)
        
            
        elif datapath.id == 2:
                self.logger.info("Received PacketIn from s2")
                #self.logger.info("s2 datapath %s",datapath)
                self.datapath_s2=datapath
                self.logger.info("s2 datapath %s",datapath)

        elif datapath.id == 3:
                self.logger.info("Received PacketIn from s3")
                #self.logger.info("s3 datapath %s",datapath)
                self.datapath_s3=datapath
                self.logger.info("s3 datapath %s",datapath)
        
        elif datapath.id == 4:
                self.logger.info("Received PacketIn from s4")
                #self.logger.info("s3 datapath %s",datapath)
                self.datapath_s4=datapath
                self.logger.info("s4 datapath %s",datapath)
        
        elif datapath.id == 5:
                self.logger.info("Received PacketIn from s5")
                #self.logger.info("s3 datapath %s",datapath)
                self.datapath_s5=datapath
                self.logger.info("s5 datapath %s",datapath)
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if not self.drop_added or not self.first_syn_ack_received:
            msg = ev.msg
            datapath = msg.datapath
            
            ofproto = datapath.ofproto
            pkt = packet.Packet(msg.data)
            in_port=msg.match['in_port']
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if ipv4_pkt:
                src_ip = ipv4_pkt.src
                self.ip_to_port[src_ip] = in_port
                #.logger.info("Recorded IP %s with In-Port %s", src_ip, in_port)
            #self.logger.info("dictionary %s",self.ip_to_port)
            #self.logger.info("in_port_list %s",self.in_port_list)
            if len(self.ip_to_port)>1:
                self.src_in_port=list(self.ip_to_port.values())[0]
                self.dst_in_port=list(self.ip_to_port.values())[1]


        
            
            eth = pkt.get_protocol(ethernet.ethernet)
            
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                    # ignore lldp packet
                    return
           

            dst = eth.dst
            src = eth.src

            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.match['in_port'])

            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            tcp_pkt = pkt.get_protocol(tcp.tcp) if ipv4_pkt else None

            #self.logger.info("TCP :%s", tcp_pkt)
           

            self.in_and_out(self.datapath_s3,in_port=1,out_port=2,priority=1)
            self.in_and_out_controller(self.datapath_s3,in_port=1,out_port=2,priority=2)
            self.in_and_out(self.datapath_s3,in_port=2,out_port=1,priority=1)
            self.in_and_out_controller(self.datapath_s3,in_port=2,out_port=1,priority=2)
            self.in_and_out(self.datapath_s4,in_port=1,out_port=2,priority=1)
            self.in_and_out_controller(self.datapath_s4,in_port=1,out_port=2,priority=2)
            self.in_and_out(self.datapath_s4,in_port=2,out_port=1,priority=1)
            self.in_and_out_controller(self.datapath_s4,in_port=2,out_port=1,priority=2)
            self.in_and_out(self.datapath_s5,in_port=1,out_port=2,priority=1)
            self.in_and_out_controller(self.datapath_s5,in_port=1,out_port=2,priority=2)
            self.in_and_out(self.datapath_s5,in_port=2,out_port=1,priority=1)
            self.in_and_out_controller(self.datapath_s5,in_port=2,out_port=1,priority=2)
            self.in_and_out(self.datapth_s1,in_port=2,out_port=1,priority=1)
            self.in_and_out(self.datapth_s1,in_port=3,out_port=1,priority=1)
            self.in_and_out(self.datapth_s1,in_port=4,out_port=1,priority=1)
            self.in_and_out(self.datapath_s2,in_port=2,out_port=1,priority=1)
            self.in_and_out(self.datapath_s2,in_port=3,out_port=1,priority=1)
            self.in_and_out(self.datapath_s2,in_port=4,out_port=1,priority=1)
            self.in_and_out(self.datapath_s2,in_port=1,out_port=2,priority=1)
            self.dst_ip_dst_port_s2(self.datapath_s2,'10.0.0.2',2)
            self.select_route_syn(self.datapth_s1,group_id=1)
            self.select_route_syn(self.datapath_s2,group_id=1)
            self.use_group(self.datapth_s1,in_port=1,group_id=1)
            self.use_group(self.datapath_s2,in_port=1,group_id=1)


            
            if tcp_pkt and hasattr(tcp_pkt, 'has_flags') and tcp_pkt.has_flags(tcp.TCP_SYN)and not tcp_pkt.has_flags(tcp.TCP_ACK)and ipv4_pkt.src == "10.0.0.1":
                    self.syn_count += 1
                    self.logger.info("SYN count: %s", self.syn_count)
                    self.logger.info("SYN ack count: %s", self.syn_ack_count)
                        

                    self.src_ip= ipv4_pkt.src
                    self.dst_ip=ipv4_pkt.dst
                    self.src_port=tcp_pkt.src_port
                    self.dst_port=tcp_pkt.dst_port
                    self.src_mac=eth.src
                    self.dst_mac=eth.dst

                    src_ip=ipv4_pkt.src
                    dst_ip=ipv4_pkt.dst
                        
                    self.logger.info("datapath %s",datapath)
                    self.logger.info("in port %s",self.src_in_port)
                    self.logger.info("dst ip %s",self.dst_ip)
                    self.logger.info("out_port %s",self.dst_in_port)

                    if datapath.id==3:
                            self.logger.info("pass s3")
                            self.syn_ack_s2(self.datapath_s2,self.src_ip,self.src_port,2,10,2)
                            self.logger.info("add syn_ack_s2")
                        
                            self.ack_s1(self.datapth_s1, self.src_ip, self.dst_port, self.dst_ip, self.src_port,2, 2, 10)
                            self.logger.info("add ack_s1")

                    elif datapath.id==4:
                            self.syn_ack_s2(self.datapath_s2,self.src_ip,self.src_port,3,10,2)
                            self.logger.info("add syn_ack_s2")
                            self.ack_s1(self.datapth_s1, self.src_ip, self.dst_port, self.dst_ip, self.src_port,3, 2, 10)
                            self.logger.info("add ack_s1")
                    elif datapath.id==5:
                            self.logger.info('pass s5')
                            self.syn_ack_s2(self.datapath_s2,self.src_ip,self.src_port,4,10,2)
                            self.logger.info("add syn_ack_s2")
                            self.ack_s1(self.datapth_s1, self.src_ip, self.dst_port, self.dst_ip, self.src_port,4, 2, 10)
                            self.logger.info("add ack_s1")
                    else:
                            self.logger.info("datapath %s",datapath.id)
                    

                    
            if tcp_pkt and hasattr(tcp_pkt, 'has_flags') and tcp_pkt.has_flags(tcp.TCP_SYN) and tcp_pkt.has_flags(tcp.TCP_ACK) :
                    self.logger.info("Received SYN+ACK")
                    self.syn_ack_count += 1
                    self.logger.info("SYN ack count: %s", self.syn_ack_count)
                    self.logger.info("SYN count: %s", self.syn_count)

                    
                    #add syn flow table 1 flow entry
                    if ipv4_pkt.dst == "10.0.0.1":
                        self.logger.info("flow table 1 datapath %s",datapath)
                        self.logger.info('flow table 1 src_ip %s',self.src_ip)
                        self.logger.info('flow table 1 src port %s',self.src_port)
                        self.logger.info('flow table 1 dst ip %s',self.dst_ip)
                        self.logger.info('flow table 1 dst port %s',self.dst_port)
                        self.logger.info('flow table 1 hard timeout %s',int(self.hard_time_out))
                        try:
                            self.add_flow_entry_in_flow_table_1(datapath=datapath,src_ip=self.src_ip,src_port=self.src_port,dst_ip=self.dst_ip,dst_port=self.dst_port,hard_timeout=int(self.hard_time_out),priority=1,table_id=1) #table 1, priority=1
                        except Exception as e:
                            self.logger.info("Error : %s" %(e))
                            pass

            if tcp_pkt and hasattr(tcp_pkt, 'has_flags') and tcp_pkt.has_flags(tcp.TCP_ACK) and not tcp_pkt.has_flags(tcp.TCP_SYN)and not tcp_pkt.has_flags(tcp.TCP_FIN) :
                    self.logger.info("ACK from client")
                    self.hoc_count=0
                

                

            if tcp_pkt and hasattr(tcp_pkt, 'has_flags') and tcp_pkt.has_flags(tcp.TCP_ACK) and not tcp_pkt.has_flags(tcp.TCP_SYN) and tcp_pkt.has_flags(tcp.TCP_FIN):
                    self.logger.info('ACk+FIN')

            
       
                    # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = msg.match['in_port']

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

                # install a flow to avoid packet_in next time
                # if out_port != ofproto.OFPP_FLOOD:
                # self.add_flow(datapath, msg.match['in_port'], dst, src, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
                actions=actions, data=data)
            datapath.send_msg(out)

            


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            current_time=time.time()

            if current_time - self.last_list_clear_time >= 1000:
                self.last_list_clear_time = current_time

                # clear self.SN_list
                if len(self.SN_list) > 20:
                     keep_index = len(self.SN_list) // 2
                     self.SN_list = self.SN_list[keep_index:]
                     self.logger.info("Cleared the first half of SN_list")
                else:
                  self.logger.info("SN_list has 1 or 0 elements, not clearing")
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1000)

    def _request_stats(self, datapath):
        self.logger.info('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        try :
            body = ev.msg.body

            self.logger.info('datapath         '
                            'in-port  eth-dst           '
                            'out-port packets  bytes')
            self.logger.info('---------------- '
                            '-------- ----------------- '
                            '-------- -------- --------')
            for stat in sorted([flow for flow in body if flow.priority == 1],
                            key=lambda flow: (flow.match['in_port'],
                                                flow.match['eth_dst'])):
                self.logger.info('%016x %8x %17s %8x %8d %8d',
                                ev.msg.datapath.id,
                                stat.match['in_port'], stat.match['eth_dst'],
                                stat.instructions[0].actions[0].port,
                                stat.packet_count, stat.byte_count)
        except KeyError:
            pass

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)