/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

/*
  Validation of Ethernet header, make sure this is a valid ethernet packet that we expect
  1 type is either 0x0806 (ARP) or 0x0800 (IPv4), otherwise discard this packet
  2 dest MAC address is of `iface`, or is of broadcast address FF:FF:FF:FF:FF:FF
*/
struct ethernet_hdr*
SimpleRouter::validateEther(const Buffer& packet, const Interface* iface) {
  if (packet.size() < 14) { 
    std::cerr << "packet size too small" << std::endl; 
    return nullptr;
  }
  struct ethernet_hdr* pEther = (struct ethernet_hdr*)packet.data();
  uint16_t type = ethertype((uint8_t*)pEther);
  if (type != ethertype_arp && type != ethertype_ip) {
    std::cerr << "Neither ARP or IP packet received: Type=" << std::hex << unsigned(type) << std::endl;
    return nullptr;
  }
  if (0 == memcmp(pEther->ether_dhost, iface->addr.data(), 6)) {
    std::cerr << "Dest MAC is to this router" << std::endl;
  } else {
    std::cerr << "Dest MAC is not this router" << std::endl;
    if ((packet[0] & packet[1] & packet[2] & packet[3] & packet[4] & packet[5]) == 0xff) {
      std::cerr << "Dest MAC is broadcast" << std::endl;
    } else {
      std::cerr << "Dest MAC is not broadcast address" << std::endl;
      //std::cerr << "Dest MAC: " << macToString(pEther->) << std::endl;
      return nullptr;
    } 
  } 
  return pEther;
}

/*
  Validation of ARP pacekt
  1 Hardware Type: 0x0001 (Ethernet)
  2 Protocol Type: 0x0800 (IPv4)
  3 Opcode: 1 (ARP request) 2 (ARP reply)
  4 HW addr len: number of octets in the specified hardware address. Ethernet has 6-octet addresses, so 0x06.
  5 Prot addr len: number of octets in the requested network address. IPv4 has 4-octet addresses, so 0x04.
*/
struct arp_hdr*
SimpleRouter::validateArp(const Buffer& packet) {
  struct arp_hdr *pARP;
  if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)) {
    std::cerr << "Incorrect ARP size: " << packet.size()-sizeof(struct ethernet_hdr) << std::endl;
    return nullptr;
  }
  pARP = (struct arp_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
  if (ntohs(pARP->arp_hrd) != arp_hrd_ethernet) {
    std::cerr << "ARP hardware type is not ethernet: " << std::hex << unsigned(ntohs(pARP->arp_hrd)) << std::endl;
    return nullptr;
  }
  if (ntohs(pARP->arp_pro) != 0x0800) {
    std::cerr << "ARP protocol is not IPv4: " << std::hex << unsigned(ntohs(pARP->arp_pro)) << std::endl;
    return nullptr;
  }
  if (ntohs(pARP->arp_op) != 1 && ntohs(pARP->arp_op) != 2) {
    std::cerr << "ARP is neither request nor reply, opcode: " << std::hex << unsigned(ntohs(pARP->arp_op)) << std::endl;
    return nullptr;
  }
  if (pARP->arp_hln != 0x06) {
    std::cerr << "ARP hw addr len is not 6, hln: " << std::hex << pARP->arp_hln << std::endl;
    return nullptr;
  }
  if (pARP->arp_pln != 0x04) {
    std::cerr << "ARP request network addr len is not 4, hln: " << std::hex << pARP->arp_pln << std::endl;
    return nullptr;
  }
  return pARP;
}

void 
SimpleRouter::makeArpReplyPacket(Buffer& reply, const Interface* iface, struct ethernet_hdr* pEther, struct arp_hdr* pARP) {
  struct ethernet_hdr *ether = (struct ethernet_hdr*)reply.data();
  memcpy(ether->ether_dhost, pEther->ether_shost, 6);
  memcpy(ether->ether_shost, pEther->ether_dhost, 6);
  ether->ether_type = pEther->ether_type;

  struct arp_hdr *arp_reply = (struct arp_hdr*)((uint8_t*)reply.data()+sizeof(struct ethernet_hdr));
  arp_reply->arp_op = htons(2);
  memcpy(arp_reply->arp_sha, iface->addr.data(), 6);
  arp_reply->arp_sip = htonl(iface->ip);
  memcpy(arp_reply->arp_tha, pARP->arp_sha, 6);
  arp_reply->arp_tip = pARP->arp_sip;
}

void
SimpleRouter::processIncommingArp(const Buffer& packet, const Interface* iface, struct ethernet_hdr* pEther) {
  struct arp_hdr *pArp = validateArp(packet);
  if (pArp == nullptr) {
    return;
  }
  if (ntohs(pArp->arp_op) == 1) { // incomming arp request
    if (ntohl(pArp->arp_tip) == iface->ip) {
      Buffer reply = packet;
      makeArpReplyPacket(reply, iface, pEther, pArp);
      sendPacket(reply, iface->name);
    } else {
      std::cerr << "ARP request dest not to router: " << std::endl;
      print_addr_ip(*(struct in_addr*)&(pArp->arp_tip));
    }
    return;
  } else { // incomming arp reply
    std::cerr << "ARP reply received" << std::endl;
    Buffer mac(pArp->arp_sha, pArp->arp_sha + 6);
    uint32_t ip = ntohl(pArp->arp_sip);
    auto arp_entry = m_arp.lookup(ip);
    if (arp_entry->mac != mac) {
      std::cerr << "ARP reply, new entry" << std::endl;
      auto pending_request = m_arp.insertArpEntry(mac, ip);
      if (pending_request != nullptr) {
        std::cerr << "Remove queued request" << std::endl;
        // how to remove a ArpRequestEntry?
        //m_arp.removeRequest(arp_entry);
      } else {
        std::cerr << "No queued request to remove" << std::endl;
      }
    } else {
      std::cerr << "ARP reply, arp entry already exists" << std::endl;
    }
  }
  return;
}



/*
    2.4 For each incoming IPv4 packet, your router should verify its checksum and the minimum length of an IP packet
    2.5 Your router should classify datagrams into (1) destined to the router (to one of the IP addresses of the router), and (2) datagrams to be forwarded:
      For (1), if packet carries ICMP payload, it should be properly dispatched. Otherwise, discarded (a proper ICMP error response is NOT required for this project).
      For (2), your router should use the longest prefix match algorithm to find a next-hop IP address in the routing table and attempt to forward it there
    2.6 For each forwarded IPv4 packet, your router should correctly decrement TTL and recompute the checksum.
*/
struct ip_hdr*
SimpleRouter::validateIPv4(const Buffer& packet) {
  struct ip_hdr* pIPv4;
  int ip_hdr_len;
  uint16_t checksum;
  if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr)) {
    std::cerr << "IP packet size too small" << std::endl;
    return nullptr;
  }
  pIPv4 = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
  ip_hdr_len = 4 * (pIPv4->ip_hl);
  if (packet.size() < sizeof(struct ethernet_hdr) + ip_hdr_len) {
    std::cerr << "IP packet size too small" << std::endl;
    return nullptr;
  }
  checksum = cksum((uint8_t*)pIPv4, ip_hdr_len);
  if (checksum != 0) {
    std::cerr << "IP header checksum is not correct: " << std::hex << unsigned(checksum) << std::endl;
    return nullptr;
  }
  return pIPv4;
}

void
SimpleRouter::processIncommingIcmp(const Buffer& packet, const Interface* iface, struct ethernet_hdr* pEther, struct ip_hdr* pIPv4) {
  struct icmp_hdr *pIcmp;
  uint32_t dip = ntohl(pIPv4->ip_dst);
  const auto routing_entry = m_routingTable.lookup(dip);
  const auto arp_entry = m_arp.lookup(routing_entry.gw);
  // make a new packet, and send it via entry.ifName 
  Buffer forward = packet;
  struct ethernet_hdr *pForwardEther = (struct ethernet_hdr*)forward.data();
  struct ip_hdr *pForwardIPv4 = (struct ip_hdr*)((uint8_t*)forward.data() + sizeof(struct ethernet_hdr)); 
      
  const auto iface_forward = findIfaceByName(routing_entry.ifName);
  // dispatch ICMP
  if (packet.size() != sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(struct icmp_hdr)) {
    std::cerr << "ICMP packet size invalide: " << packet.size() - (sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(struct icmp_hdr)) << std::endl;
    return;
  }
  pIcmp = (struct icmp_hdr*)((uint8_t*)pIPv4 + sizeof(struct ip_hdr));
  int icmp_type = pIcmp->icmp_type;
  int icmp_code = pIcmp->icmp_code;
  // Router expect only Echo-request
  if (icmp_type == 8 && icmp_code == 0) {
    //reply an Echo Reply:
    Buffer replyICMP = packet;
    // prepare 
    struct ethernet_hdr *pIcmpEther = (struct ethernet_hdr*)replyICMP.data();
    struct ip_hdr *pIcmpIPv4 = (struct ip_hdr*)((uint8_t*)replyICMP.data() + sizeof(struct ethernet_hdr)); 
    struct icmp_hdr *pIcmpICMP = (struct icmp_hdr*)((uint8_t*)pIcmpIPv4 + sizeof(struct ip_hdr));
    //const auto iface_forward = findIfaceByName(routing_entry.ifName);
    // prepare ethernet header
    memcpy(pIcmpEther->ether_shost, iface_forward->addr.data(), 6);
    memcpy(pIcmpEther->ether_dhost, arp_entry->mac.data(), 6); 
    // prepare ip header, convert all fields to host order
    // total length, identification, offset, checksum, 
    // source addr, dest addr, options + padding
    pIcmpIPv4->ip_len = ntohs(pIcmpIPv4->ip_len);
    pIcmpIPv4->ip_id = ntohs(pIcmpIPv4->ip_id);
    pIcmpIPv4->ip_off = ntohs(pIcmpIPv4->ip_off);
    pIcmpIPv4->ip_src = ntohl(pIcmpIPv4->ip_src);
    pIcmpIPv4->ip_dst = ntohl(pIcmpIPv4->ip_dst);
    pIcmpIPv4->ip_sum = 0;
    pIcmpIPv4->ip_ttl -= 1;
    if (pIcmpIPv4->ip_ttl == 0) {
      std::cerr << "IP header ttl = 0" << std::endl;
    } 
    // compute checksum
    pIcmpIPv4->ip_sum = cksum(pIcmpIPv4, sizeof(struct ip_hdr));
    // convert ip header fields back to network order
    pIcmpIPv4->ip_len = htons(pIcmpIPv4->ip_len);
    pIcmpIPv4->ip_id = htons(pIcmpIPv4->ip_id);
    pIcmpIPv4->ip_off = htons(pIcmpIPv4->ip_off);
    pIcmpIPv4->ip_src = htonl(pIcmpIPv4->ip_src);
    pIcmpIPv4->ip_dst = htonl(pIcmpIPv4->ip_dst);
    sendPacket(forward, routing_entry.ifName);
  } else {
    std::cerr <<"ICMP unexpected type" << unsigned(icmp_type) << ", or code: " << unsigned(icmp_code) << std::endl;
  }
}

void 
SimpleRouter::forwardIPv4Packet(const Buffer& packet, struct ethernet_hdr* pEther, struct ip_hdr* pIPv4) {
/*
struct RoutingTableEntry {
  uint32_t dest;
  uint32_t gw;
  uint32_t mask;
  std::string ifName;
};
*/
  
/*
struct ArpEntry {
  Buffer mac;
  uint32_t ip = 0; //< IP addr in network byte order
  time_point timeAdded;
  bool isValid = false;
};
*/
  uint32_t dip = ntohl(pIPv4->ip_dst);
  const auto routing_entry = m_routingTable.lookup(dip);
  const auto arp_entry = m_arp.lookup(routing_entry.gw);
  // make a new packet, and send it via entry.ifName 
  Buffer forward = packet;
  struct ethernet_hdr *pForwardEther = (struct ethernet_hdr*)forward.data();
  struct ip_hdr *pForwardIPv4 = (struct ip_hdr*)((uint8_t*)forward.data() + sizeof(struct ethernet_hdr)); 
      
  const auto iface_forward = findIfaceByName(routing_entry.ifName);
  // prepare ethernet header
  memcpy(pForwardEther->ether_shost, iface_forward->addr.data(), 6);
  memcpy(pForwardEther->ether_dhost, arp_entry->mac.data(), 6); 
  // prepare ip header, convert all fields to host order
  // total length, identification, offset, checksum, 
  // source addr, dest addr, options + padding
  pForwardIPv4->ip_len = ntohs(pForwardIPv4->ip_len);
  pForwardIPv4->ip_id = ntohs(pForwardIPv4->ip_id);
  pForwardIPv4->ip_off = ntohs(pForwardIPv4->ip_off);
  pForwardIPv4->ip_src = ntohl(pForwardIPv4->ip_src);
  pForwardIPv4->ip_dst = ntohl(pForwardIPv4->ip_dst);
  pForwardIPv4->ip_sum = 0;
  pForwardIPv4->ip_ttl -= 1;
  if (pForwardIPv4->ip_ttl == 0) {
    std::cerr << "IP header ttl = 0" << std::endl;
  } 
  // compute checksum
  pForwardIPv4->ip_sum = cksum(pForwardIPv4, sizeof(struct ip_hdr));
  // convert ip header fields back to network order
  pForwardIPv4->ip_len = htons(pForwardIPv4->ip_len);
  pForwardIPv4->ip_id = htons(pForwardIPv4->ip_id);
  pForwardIPv4->ip_off = htons(pForwardIPv4->ip_off);
  pForwardIPv4->ip_src = htonl(pForwardIPv4->ip_src);
  pForwardIPv4->ip_dst = htonl(pForwardIPv4->ip_dst);
  sendPacket(forward, routing_entry.ifName);
  
}


void 
SimpleRouter::processIncommingIPv4(const Buffer& packet, const Interface* iface, struct ethernet_hdr* pEther) {
  struct icmp_hdr *pIcmp;
  struct ip_hdr *pIPv4 = validateIPv4(packet); 
  if (pIPv4 == nullptr) {
    return;
  }
  uint32_t dip = ntohl(pIPv4->ip_dst);
  const Interface* iface_dest = findIfaceByIp(dip);
  if (iface_dest != nullptr) { // dest to router
    std::cerr << "IP packet to router interface" << std::endl;
    processIncommingIcmp(packet, iface, pEther, pIPv4);
  } else { // dest to other addr
    std::cerr << "IP packet to forward" << std::endl;
    forwardIPv4Packet(packet, pEther, pIPv4);
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  struct ethernet_hdr *pEther; 
  uint16_t type;

  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }
  std::cerr << getRoutingTable() << std::endl;
  // My Implementation
  if ((pEther = validateEther(packet, iface)) == nullptr) {
    return;
  }
  if (ethertype((uint8_t*)pEther) == ethertype_arp) { // incomming arp
    processIncommingArp(packet, iface, pEther);
  } else { // incomming ipv4
    processIncommingIPv4(packet, iface, pEther);
  }
  return;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
