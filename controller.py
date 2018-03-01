
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet.tcp import packet_utils




class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.ip_mac= {}
##################################################################
	self.ip_mac["10.0.0.1"] = "00:00:00:00:00:01"
        self.ip_mac["10.0.0.2"] = "00:00:00:00:00:02"
        self.ip_mac["10.0.0.3"] = "00:00:00:00:00:03"
        self.ip_mac["10.0.0.4"] = "00:00:00:00:00:04"
###################################################################	
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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
#######################################################################
	switchno = datapath.id
	###### switch 1   ######
	if switchno == 1:
		## TCP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.2', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.3', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.4', 10, 3)
		## ICMP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 3)
		## UDP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.4', 10, 3)
		## direct http packets from h1 to h3 to the controller ##
		match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP, ipv4_src='10.0.0.1', ipv4_dst = '10.0.0.3', ip_proto= inet.IPPROTO_TCP, tcp_dst=80)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 30, match,actions)
	##### switch 2 #####
	elif switchno == 2:
		## TCP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.2', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.3', 10, 3)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.4', 10, 3)
		## ICMP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 3)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 3)
		## UDP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.4', 10, 1)
		## drop UDP traffic from h2 to h3 ##
		match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                    ipv4_src = '10.0.0.2',
                                    ipv4_dst = '10.0.0.3',
                                    ip_proto = inet.IPPROTO_UDP)
                actions = []
            	self.add_flow(datapath, 30, match, actions)
	## switch 3 ##
	elif switchno == 3:
		## TCP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.3', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.4', 10, 3)
		## ICMP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 3)
		## UDP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 3)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.4', 10, 3)
		## DRop UDP traffic from h3 to h2 ##
		match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                    ipv4_src = '10.0.0.3',
                                    ipv4_dst = '10.0.0.2',
                                    ip_proto = inet.IPPROTO_UDP)
            	actions = []
            	self.add_flow(datapath, 30, match, actions)
		match1 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP, ipv4_src='10.0.0.3', ipv4_dst = '10.0.0.1', ip_proto= inet.IPPROTO_TCP, tcp_dst=80)
		actions1 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 35 , match1,actions1)

	##  switch 4 ##
	elif switchno == 4:
		## TCP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.2', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.3', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_TCP, '10.0.0.4', 10, 3)
		## ICMP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 3)
		## UDP forwarding ##
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 1)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 2)
		self.add_rules(datapath, inet.IPPROTO_UDP, '10.0.0.4', 10, 3)
			
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth.ethertype

	## IP ##
        if ethertype == ether.ETH_TYPE_IP:
            self.handle_ip(datapath, in_port, pkt)
            return
        
	## ARP ## 
        if ethertype == ether.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, pkt)
            return

        
    def add_layer4_rules(self, datapath, ip_proto, ipv4_dst = None, priority = 1, fwd_port = None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ip_proto = ip_proto,
                                ipv4_dst = ipv4_dst)
        self.add_flow(datapath, priority, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def handle_arp(self, datapath, in_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # parse out the ethernet and arp packet
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        # obtain the MAC of dst IP  
        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]

        arp_reply= packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(dst = eth_pkt.src,
                                                 src = arp_resolv_mac,
                                                 ethertype = ether.ETH_TYPE_ARP))
        arp_reply.add_protocol(arp.arp(hwtype = 1,
                                       proto = 0x0800, 
                                       hlen = 6, 
                                       plen = 4,
                                       opcode=2,
                                       src_mac=arp_resolv_mac,
                                       src_ip=arp_pkt.dst_ip,
                                       dst_mac=eth_pkt.src,
                                       dst_ip=arp_pkt.src_ip))
        arp_reply.serialize()
        
        # send the Packet Out mst to back to the host who is initilaizing the ARP
        actions = [parser.OFPActionOutput(in_port)];
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                  ofproto.OFPP_CONTROLLER, actions,
                                  arp_reply.data)
        datapath.send_msg(out)

    
    def handle_ip(self, datapath, in_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4) 

        if datapath.id == 1 and ipv4_pkt.proto == inet.IPPROTO_TCP:
            tcp_pkt = pkt.get_protocol(tcp.tcp) 
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            tcp_rst = packet.Packet()
	    tcp_rst.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
			                       dst=eth_pkt.src,
					            src=eth_pkt.dst))
            tcp_rst.add_protocol(ipv4.ipv4(proto=6,dst=ipv4_pkt.src,
					    src=ipv4_pkt.dst))
            tcp_rst.add_protocol(tcp.tcp(src_port=tcp_pkt.dst_port,
					 dst_port=tcp_pkt.src_port,seq=0,
					 ack=tcp_pkt.seq+1,
					 bits=0x04))	    
            tcp_rst.serialize()
            self.logger.info("packet-out %s" %(tcp_rst,))
       
            actions = [parser.OFPActionOutput(in_port)];
            out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                      ofproto.OFPP_CONTROLLER, actions,
                                      tcp_rst.data)
            datapath.send_msg(out)
            self.logger.info("packet-out %s" %(out,))
	if datapath.id == 3 and ipv4_pkt.proto == inet.IPPROTO_TCP:
            tcp_pkt = pkt.get_protocol(tcp.tcp) 
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            tcp_rst = packet.Packet()
	    tcp_rst.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
			                       dst=eth_pkt.src,
					            src=eth_pkt.dst))
            tcp_rst.add_protocol(ipv4.ipv4(proto=6,dst=ipv4_pkt.src,
					    src=ipv4_pkt.dst))
            tcp_rst.add_protocol(tcp.tcp(src_port=tcp_pkt.dst_port,
					 dst_port=tcp_pkt.src_port,seq=0,
					 ack=tcp_pkt.seq+1,
					 bits=0x04))	    
            tcp_rst.serialize()
            self.logger.info("packet-out %s" %(tcp_rst,))

            actions = [parser.OFPActionOutput(in_port)];
            out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                      ofproto.OFPP_CONTROLLER, actions,
                                      tcp_rst.data)
            datapath.send_msg(out)
            self.logger.info("packet-out %s" %(out,))
