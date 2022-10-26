#Giorgos Dovas csd4193
from distutils.cmd import Command
from pydoc import cli
from struct import pack

from symbol import return_stmt
from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IP_ANY, EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
log = core.getLogger()
FLOW_IDLE_TIMEOUT = 10
import time
import random
import json # addition to read configuration from file


class SimpleLoadBalancer(object):

    
    # initialize SimpleLoadBalancer class instance
    def __init__(self, lb_mac = None, service_ip = None, 
                 server_ips = [], user_ip_to_group = {}, server_ip_to_group = {}):
        
        # add the necessary openflow listeners
        core.openflow.addListeners(self) 
        log.info("\n=====\nINITIALISING\n======")
        # set class parameters
        # write your code here!!! (DONE)
        
        # Dovas: Init
        # IP , MAC, PORT
        self.arpTable  = {}
        
        self.macToPort = {}
        self.ClientToServer={}
        self.IPtoMAC = {}
        
        #self.fakeways = set(lb_mac)
        self.lb_mac = lb_mac         # the load balancer MAC with which the switch responds to ARP requests from users/servers   
        self.service_ip = service_ip # the service IP that is publicly visible from the users' side 
        self.server_ips = server_ips
        self.user_ip_to_group = user_ip_to_group    # map users (IPs) to service groups (e.g., 10.0.0.5 to 'red')   
        self.server_ip_to_group = server_ip_to_group     # map servers (IPs) to service groups (e.g., 10.0.0.1 to 'blue')

            
        return


    # respond to switch connection up event
    # (DONE)
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        # write your code here!!!
        # Dovas: Connections established: for each server send a arp request (DONE)
        for serverIP in self.server_ips:
            #send_proxied_arp_request(self,self.connection,serverIP)
            r = arp()
            r.hwtype = r.HW_TYPE_ETHERNET
            r.prototype = r.PROTO_TYPE_IP
            r.hwlen = 6
            r.protolen = r.protolen
            r.opcode = r.REQUEST
            r.hwdst = ETHER_BROADCAST
            r.protodst = serverIP
            r.protosrc = self.service_ip
            r.hwsrc = self.lb_mac
            e = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac,
                     dst=ETHER_BROADCAST)
            e.set_payload(r)
            log.debug("SWITCH: Sending ARP request to server with ip:",serverIP,"\n\tPacket sent: ",e )
            action_output = of.ofp_action_output(port = of.OFPP_FLOOD)
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(action_output)
            #msg.in_port = of.OFPP_NONE # cause the packet is generated at the controller
            event.connection.send(msg)
            
        return


    # update the load balancing choice for a certain client
    def update_lb_mapping(self, client_ip):
        # write your code here!!!
        
        pass
    

    # send ARP reply "proxied" by the controller (on behalf of another machine in network)
    # (DONE?)
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        # write your code here!!!
        reply_src = packet.payload.protodst
        reply_dst = packet.payload.protosrc
        arp_reply = arp()
        
        arp_reply.hwtype = packet.payload.hwtype
        arp_reply.prototype = packet.payload.prototype
        arp_reply.protolen = packet.payload.protolen
        arp_reply.hwlen = packet.payload.hwlen
        arp_reply.hwsrc = requested_mac
        arp_reply.hwdst = packet.src
        arp_reply.opcode = arp_reply.REPLY
        arp_reply.protosrc = reply_src
        arp_reply.protodst = reply_dst
        
        ether = ethernet(type = packet.type,src=requested_mac,dst=packet.src)
        ether.set_payload(arp_reply)
        
        # print(reply_src,": Answering ARP for ",reply_dst)
        log.info("%s Answering ARP for %s" %(reply_src,reply_dst))
        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        
        
        connection.send(msg)
                
        return


    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    # (DONE?)
    def send_proxied_arp_request(self, connection, ip):
        r = arp()
        r.hwsrc = self.lb_mac
        r.hwdst = ETHER_BROADCAST
        r.opcode = r.REQUEST
        r.protosrc = self.service_ip
        r.protodst=ip
        
        e = ethernet(type = ethernet.ARP_TYPE,src=self.lb_mac,dst=ETHER_BROADCAST)
        e.set_payload(r)
        
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))      
        
        connection.send(msg)  
        return
    
    # install flow rule from a certain client to a certain server
    # (DONE?)pain
    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        actions = []
        actions.append(of.ofp_action_dl_addr.set_dst(self.IPtoMAC[server_ip]))
        actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        actions.append(of.ofp_action_output(port = self.macToPort[self.IPtoMAC[server_ip]]))
        packet = buffer_id.parsed
        match = of.ofp_match.from_packet(packet,self.macToPort[self.IPtoMAC[client_ip]])
        msg = of.ofp_flow_mod(command = of.OFPFC_ADD,
                              data = buffer_id.ofp,
                              actions = actions,
                              match = match
                              )
        
        log.info ("Installing flow rule client (%s) to server (%s)" %(client_ip,server_ip))
        connection.send(msg)
        
        
        
        return


    # install flow rule from a certain server to a certain client
    # (DONE?)
    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        # write your code here!!!
        actions = []
        actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
        actions.append(of.ofp_action_dl_addr.set_dst(self.IPtoMAC[client_ip]))
        actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
        actions.append(of.ofp_action_output(port = self.macToPort[self.IPtoMAC[client_ip]]))
        packet = buffer_id.parsed
        match = of.ofp_match.from_packet(packet, self.macToPort[self.IPtoMAC[server_ip]])
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                              data = buffer_id.ofp,
                              actions= actions,
                              match = match
                              )
        log.info ("Installing flow rule server (%s) to client (%s)" %(server_ip,client_ip))
        connection.send(msg)
        return


    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port

        if packet.type == packet.ARP_TYPE:
            # print("Arp packet arrived:" , packet," Packet srcIP: ",packet.payload.protosrc)
            
            # write your code here!!!
            if packet.payload.protosrc not in self.server_ips: # ARP packet arrived from a client
                log.info("Packet from client %s"%(packet.payload.protosrc))
                if not self.macToPort.has_key(packet.src):
                    self.IPtoMAC.update({packet.payload.protosrc:packet.src})
                    self.macToPort.update({packet.src:inport})
                    self.arpTable.update({packet.payload.protosrc : (packet.src,inport) })
                    log.info("SWITCH: Added new MAC to PORT pair ",self.macToPort)
                self.send_proxied_arp_reply(packet=packet,connection=connection,outport=inport,requested_mac=self.lb_mac)                    
                return
            
            else:
                # ARP PACKET arrived from SERVER
                log.info("Packet arrived from server %s" %(packet.payload.protosrc))
                if packet.payload.opcode == arp.REPLY:
                    if not self.macToPort.has_key(packet.src):
                        self.macToPort.update({packet.src:inport})
                        self.IPtoMAC.update({packet.payload.protosrc:packet.src})
                        self.arpTable.update({packet.payload.protosrc:(packet.src,inport)})
                        log.info("SWITCH: Added new MAC to PORT pair ",self.macToPort)
                    else:
                        self.macToPort[packet.src] = inport
                        del self.arpTable[packet.payload.protosrc]
                        self.arpTable.update({packet.payload.protosrc : (packet.src,inport)})            
                    log.info("SWITCH: UPDATED Mac to Port pair ", self.macToPort)
                    
                    return
                
                if packet.payload.opcode == arp.REQUEST :
                    self.send_proxied_arp_reply(packet=packet,connection=connection,outport=inport,requested_mac=self.lb_mac)
                    # r = arp()
                    
                    # r.hwtype = packet.payload.hwtype
                    # r.protolen = packet.payload.protolen
                    # r.prototype = packet.payload.prototype
                    # r.hwlen = packet.payload.hwlen
                    # r.hwsrc = self.lb_mac
                    # r.hwdst = packet.payload.hwsrc
                    # r.opcode = arp.REPLY
                    # r.protodst = packet.payload.protosrc
                    # r.protosrc = packet.payload.protodst
                    
                    # e = ethernet(type=packet.type,src = self.lb_mac,dst=packet.src)
                    # e.set_payload(r)
                    # # log.info("%i %i answering ARP for %i" % (packet.payload.protosrc , inport, r.protosrc))
                    # print("Sending ARP REPLY to server: %s",packet.payload.protosrc)
                    # msg = of.ofp_packet_out()
                    # msg.data = e.pack()
                    # msg.actions.append(of.ofp_action_output(port = inport))
                    # msg.in_port = inport
                    # connection.send(msg)
                    
                return
            
        elif packet.type == packet.IP_TYPE:
            
            # write your code here!!!
            ip_packet = packet.payload
            log.info("IP_TYPE packet arrived (ICMP) from: %s"%(ip_packet.srcip))
            if ip_packet.srcip not in self.server_ips:  # IP packet arrived from a client
                # Select random a server to send the packet
                
                if ip_packet.dstip != self.service_ip: #falsy
                    log.info("Falsy packet arrived DROP dstip: %s",ip_packet.dstip)
                    log.info("Service IP: %s",self.service_ip)
                    return
                
                client_ip = ip_packet.srcip
                if not self.ClientToServer.has_key(client_ip):
                    index = random.randint(0,1)
                    if self.user_ip_to_group[ip_packet.srcip] == 'blue':
                        index = index + 2
                    selected_serverIP = self.server_ips[index]
                    self.ClientToServer.update({client_ip:selected_serverIP})
                else:
                    selected_serverIP = self.ClientToServer[client_ip]
                log.info("Installing rule client (%s) to server (%s)"%(client_ip,self.ClientToServer[client_ip]))
                self.install_flow_rule_client_to_server(connection=connection,outport=self.macToPort[packet.src],
                                                            client_ip=client_ip,server_ip=self.ClientToServer[client_ip]
                                                            ,buffer_id = event)
                
                
                
                
                
                return
            else:
                log.info("Paket arrived from server: %s" % (ip_packet.srcip))
                outport = self.macToPort[self.IPtoMAC[ip_packet.dstip]] #client's port
                self.install_flow_rule_server_to_client(
                    connection=connection,outport=outport, server_ip=ip_packet.srcip,
                    client_ip=ip_packet.dstip,buffer_id=event
                )
                return
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return
    
#================================================================#


# extra function to read json files
def load_json_dict(json_file):
    json_dict = {}    
    with open(json_file, 'r') as f:
        json_dict = json.load(f)
    return json_dict


# main launch routine
def launch(configuration_json_file):
    log.info("Loading Simple Load Balancer module")
    
    # load the configuration from file    
    configuration_dict = load_json_dict(configuration_json_file)   

    # the service IP that is publicly visible from the users' side   
    service_ip = IPAddr(configuration_dict['service_ip'])

    # the load balancer MAC with which the switch responds to ARP requests from users/servers
    lb_mac = EthAddr(configuration_dict['lb_mac'])
    # the IPs of the servers
    server_ips = [IPAddr(x) for x in configuration_dict['server_ips']]    

    # map users (IPs) to service groups (e.g., 10.0.0.5 to 'red')    
    user_ip_to_group = {}
    for user_ip,group in configuration_dict['user_groups'].items():
        user_ip_to_group[IPAddr(user_ip)] = group

    # map servers (IPs) to service groups (e.g., 10.0.0.1 to 'blue')
    server_ip_to_group = {}
    for server_ip,group in configuration_dict['server_groups'].items():
        server_ip_to_group[IPAddr(server_ip)] = group

    # do the launch with the given parameters
    core.registerNew(SimpleLoadBalancer, lb_mac, service_ip, server_ips, user_ip_to_group, server_ip_to_group)
    log.info("Simple Load Balancer module loaded")
