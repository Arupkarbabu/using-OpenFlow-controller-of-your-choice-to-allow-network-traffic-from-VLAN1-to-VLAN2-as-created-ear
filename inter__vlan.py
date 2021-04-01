
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.ofproto import ether
from ryu.lib.packet import vlan
from ryu.lib.packet import ipv4


#topology
#        h1
#        |         
# h2----OVS-----h4
#        |
#        h3

#VLAN configurations 
#dpid:{port1: vlanid, port2: vlanid......portn: vlanid}

access_data = {
               1:{1:100,2:200,3:100,4:200}
              }


# VLAN Utilities class
class VlanUtilities:
    """ Class of utilities used by the program """

    def __init__(self, *args):
        pass

    def get_access_ports(self, dpid, vlan_id):
        ports = []
        for port in access_data[dpid]:
            if access_data[dpid][port] == vlan_id:
                ports.append(port)
        return ports

    def get_non_vlan_port(self,dpid,vlan_id):
        ports = []
        for port in access_data[dpid]:
            if access_data[dpid][port] != vlan_id:
                ports.append(port)
        return ports

  

    def is_it_access_port(self, dpid, vlan_id, port):
        if port in access_data[dpid]:
            if vlan_id == access_data[dpid][port]:
                return True
        return False



    def is_it_non_access_port(self, dpid, vlan_id, port):
        if port in access_data[dpid]:
            if vlan_id != access_data[dpid][port]:
                return True
        return False


    def is_it_other_vlan_access_port(self, dpid, vlan_id, in_port, out_port):
        print "Called"
        #if in_port in access_data[dpid]:
        if vlan_id != access_data[dpid][out_port]:
            print "Working"
            return True
        return False

# End - VlanUtilities class

# Create instance of the VlanUtilities class
utilities = VlanUtilities()

class VLANSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(VLANSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)


    def add_flow(self, datapath, priority, table_id, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, table_id=0, match=match,instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, table_id=0, instructions=inst)
        datapath.send_msg(mod)

    def flood_packet_to_all_vlan_ports(self, msg, vlan_id, tagged):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        actions = []

        # if it is a tagged packet, untag first.
        if tagged == 1:
            actions.append(parser.OFPActionPopVlan())

        aports = utilities.get_access_ports(datapath.id, vlan_id)
        non_vlan_ports = utilities.get_non_vlan_port(datapath.id, vlan_id)
        

        (a,b,c) = (datapath.id, vlan_id, aports)
        self.logger.info("flood packet: dpid ({}) vlan_id ({}) access ports  ({}) \n".format(a,b,c))

        (x,y,z) = (datapath.id, vlan_id, non_vlan_ports)
        self.logger.info("flood packet: dpid ({}) vlan_id ({}) Non access ports  ({}) \n".format(x,y,z))

        # don't sent it back to the received port
        for port in aports:
            if port != in_port:
                actions.append(parser.OFPActionOutput(port))

        # build actions for flow to add VLAN tag to packets egressing trunk ports
        # for trunk port, push a vlan tag onto packet and send it.
        #actions.append(parser.OFPActionPushVlan(0x8100))

        # Include OpenFlow Port VLAN ID present (OFPVID_PRESENT) 
        #vid = vlan_id | ofproto_v1_3.OFPVID_PRESENT
        #actions.append(parser.OFPActionSetField(vlan_vid=vid))

        for port in non_vlan_ports:
            if port != non_vlan_ports:
                actions.append(parser.OFPActionOutput(port))
        

        # send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def forward_packet_to_a_vlan_port(self, msg, vlan_id, out_port, dst, src, tagged):
        self.logger.info("forward packet to a port {}".format(out_port))
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        actions = []

        pkt2 = packet.Packet(msg.data)
        pkt_eth = pkt2.get_protocol(ethernet.ethernet)

        if pkt_eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt2.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            self.logger.info("Packet from %s to %s", srcip,dstip)

        eth_s=pkt_eth.src
        eth_d=pkt_eth.dst


        # in port: access, out port: access/non access  (utilities.is_it_non_access_port(datapath.id, vlan_id, out_port)) or
        if (utilities.is_it_access_port(datapath.id, vlan_id, in_port) and  (utilities.is_it_access_port(datapath.id, vlan_id, out_port)) ):

            (a,b,c,d,e) = (in_port, out_port, vlan_id,eth_s, eth_d)
            self.logger.info("VLAN {} Access port {} to access port {}  Eth_S: {} Eth_D: {} \n".format(c,b,a,d,e))

            # build match and actions for flow
            actions.append(parser.OFPActionOutput(out_port))
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            # add flow to flow table
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, 0, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, 0, match,  actions) 

        else:
            (a,b,c) = (in_port, out_port, vlan_id)
            self.logger.info("Inter Vlan Not Allowed: in port {} to out port {} : VLAN {}\n".format(a,b,c))

        # packet out - if no buffer
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # //=============== Packet IN handler ===============//

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]


        # local variables
        vlan_id = 0
        tagged = 0
        dst = eth.dst
        src = eth.src

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        else:
            # identify the VLAN access port
            vlan_id = access_data[dpid][in_port]
            print "VLAN ID: ", vlan_id
            (a,b,c,d) = (dpid, src, dst, in_port)
            self.logger.info("untagged packet in  dp-id({}) src-mac({}) dst-mac({}) in-port({})\n".format(a,b,c,d))

        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        #actions = []
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info("found the matched out port {}".format(out_port))
            self.forward_packet_to_a_vlan_port(msg, vlan_id, out_port, dst, src,  tagged)
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("no match found, flood to vlan ports")
            self.flood_packet_to_all_vlan_ports(msg, vlan_id, tagged)
# End
