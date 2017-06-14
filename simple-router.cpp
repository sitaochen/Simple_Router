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




//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  struct ethernet_hdr *pEther; 
  CERR(" ");
  std::cerr << "Got packet of size " << std::dec << packet.size() << " on interface " << inIface << std::endl;
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }
  // My Code start here
  try {
    pEther = validateEther(packet, inIface);
  } catch (std::exception& e) {
    CERR(e.what())
    return;
  } catch (...) {
    CERR("Unexpected exception")
    return;
  }
  if (ethertype((uint8_t*)pEther) == ethertype_arp) { // incomming arp
    CERR("Arp packet received")
    processIncommingArp(packet, inIface);
  } else { // incomming ipv4
    CERR("IPv4 packet received")
    processIncommingIPv4(packet, inIface);
  }
  CERR(" ")
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

/******************************************************************************
* Additional Helper Functions
******************************************************************************/

struct ethernet_hdr*
SimpleRouter::validateEther(const Buffer& packet, const std::string& inIface) 
{
  if (packet.size() < 14) { 
    throw std::runtime_error("Packet size too small");
  }
  struct ethernet_hdr* pEther = (struct ethernet_hdr*)packet.data();
  uint16_t type = ethertype((uint8_t*)pEther);
  if (type != ethertype_arp && type != ethertype_ip) {
    throw std::runtime_error("Neither ARP or IP packet received: Type="+to_string_hex(unsigned(type)));
  }
  const Interface* iface = findIfaceByName(inIface);
  if (0 == memcmp(pEther->ether_dhost, iface->addr.data(), 6)) {
    CERR("Dest MAC is to this router")
  } else {
    CERR("Dest MAC is not this router")
    if ((packet[0] & packet[1] & packet[2] & packet[3] & packet[4] & packet[5]) == 0xff) {
      CERR("Dest MAC is broadcast")
    } else {
      CERR("Dest MAC is not broadcast address")
      throw std::runtime_error("Dest Mac is neither this router nor broadcast");
    } 
  } 
  return pEther;
}

struct arp_hdr*
SimpleRouter::validateArp(const Buffer& packet) 
{
  struct arp_hdr *pARP;
  if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)) {
    throw std::runtime_error("Incorrest ARP size: " + std::to_string(packet.size()-sizeof(struct ethernet_hdr)));
  }
  pARP = (struct arp_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
  if (ntohs(pARP->arp_hrd) != arp_hrd_ethernet) {
    throw std::runtime_error("ARP hardware type is not ethernet: "+to_string_hex(unsigned(ntohs(pARP->arp_hrd))));
  }
  if (ntohs(pARP->arp_pro) != 0x0800) {
    throw std::runtime_error("ARP protocol is not IPv4: " + to_string_hex(unsigned(ntohs(pARP->arp_pro))));
  }
  if (ntohs(pARP->arp_op) != 1 && ntohs(pARP->arp_op) != 2) {
    throw std::runtime_error("ARP is neither request nor reply, opcode: " + to_string_hex(unsigned(ntohs(pARP->arp_op))));
  }
  if (pARP->arp_hln != 0x06) {
    throw std::runtime_error("ARP hw addr len is not 6, hln: " + to_string_hex(pARP->arp_hln));
  }
  if (pARP->arp_pln != 0x04) {
    throw std::runtime_error("ARP request network addr len is not 4, hln: " + to_string_hex(pARP->arp_pln));
  }
  return pARP;
}

struct ip_hdr*
SimpleRouter::validateIPv4(const Buffer& packet) 
{
  struct ip_hdr* pIPv4;
  int ip_hdr_len;
  uint16_t checksum;
  if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr)) {
    throw std::runtime_error("IP packet size too small");
  }
  pIPv4 = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
  ip_hdr_len = 4 * (pIPv4->ip_hl);
  if (packet.size() < sizeof(struct ethernet_hdr) + ip_hdr_len) {
    throw std::runtime_error("IP packet size too small");
  }
  struct ip_hdr ipCopy = *pIPv4;
  ipCopy.ip_sum = 0;
  checksum = cksum((uint8_t*)&ipCopy, ip_hdr_len);
  if (checksum != pIPv4->ip_sum) {
    throw std::runtime_error("IP header checksum is not correct: "+to_string_hex(unsigned(checksum)));
  }
  return pIPv4;
}

struct icmp_hdr*
SimpleRouter::validateICMP(const Buffer& packet)
{
  struct ip_hdr *pIPv4; 
  struct icmp_hdr *pIcmp;

  if (packet.size() < sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(struct icmp_hdr)) {
    throw std::runtime_error("ICMP packet size invalide: " + std::to_string(packet.size() - (sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(struct icmp_hdr))));
  }
  pIPv4 = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
  pIcmp = (struct icmp_hdr*)((uint8_t*)pIPv4 + sizeof(struct ip_hdr));
  // Router expect only Echo-request
  if (!(pIcmp->icmp_type == 8 && pIcmp->icmp_code == 0)) { 
    throw std::runtime_error("ICMP unexpected type" + std::to_string(unsigned(pIcmp->icmp_type)) + ", or code: " + std::to_string(unsigned(pIcmp->icmp_code)));
  } 
  uint16_t checksum = cksum((uint8_t*)pIcmp, packet.size()-sizeof(struct ethernet_hdr)-sizeof(struct ip_hdr));
  //CERR("ICMP checksum: "+to_string_hex(unsigned(checksum)))
  if (checksum != 0xffff) {
    throw std::runtime_error("ICMP checksum incorrect");
  }
  return pIcmp;
}

void
SimpleRouter::processIncommingArp(const Buffer& packet, const std::string& inIface) 
{
  struct arp_hdr *pArp;
  try {
    pArp = validateArp(packet); 
  } catch (std::exception& e) {
    CERR(e.what())
    return;
  } catch (...) {
    CERR("Unexpected exception")
    return;
  }
  const Interface* iface = findIfaceByName(inIface);
  if (ntohs(pArp->arp_op) == 1) { // incomming arp request
    if (pArp->arp_tip == iface->ip) {
      CERR("Send Arp Reply")
      sendArpReply(packet, inIface);
    } else {
      CERR("ARP request dest not to router: ")
      //print_addr_ip(*(struct in_addr*)&(pArp->arp_tip));
    }
    return;
  } else if (ntohs(pArp->arp_op) == 2) { // incomming arp reply
    CERR("Process Arp Reply")
    processArpReply(packet);
  } else {
    CERR("Invalid Arp type: "+std::to_string(unsigned(ntohs(pArp->arp_op))))
  }
  return;
}

void 
SimpleRouter::processIncommingIPv4(const Buffer& packet, const std::string& inIface) 
{
  struct ip_hdr *pIPv4; 
  try {
    pIPv4 = validateIPv4(packet);
  } catch(std::exception& e) {
    CERR(e.what())
    return;
  } catch (...) {
    CERR("Unexpected exception")
    return;
  }
  uint32_t dip = pIPv4->ip_dst;
  uint8_t protocol = pIPv4->ip_p;
  if (findIfaceByIp(dip) != nullptr) { // dest to router
    CERR("IP packet to router interface")
    if (protocol == ip_protocol_icmp) {
      CERR("process incomming icmp")
      processIncommingIcmp(packet, inIface);
    } else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp) {
      CERR("reply icmp port unreachable")
      replyIcmpPortUnreachable(packet, inIface);
    } else {
      CERR("IP packet protocol not of icmp, tcp or ucp: "+to_string_hex(unsigned(protocol)))
    }
  } else { // dest to other addr
    CERR("IP packet to other dest, ttl: "+std::to_string(unsigned(pIPv4->ip_ttl)))
    if (pIPv4->ip_ttl-1 == 0x00) {
      CERR("reply icmp time exceeded")
      replyIcmpTimeExceeded(packet, inIface);
      return;
    }
    RoutingTableEntry routing_entry;
    try {
      routing_entry = m_routingTable.lookup(dip);
      auto arp_entry = m_arp.lookup(routing_entry.gw);
      // check forwarding table, lookup arp
      if (arp_entry == nullptr) {
        CERR("queue arp request")
        m_arp.queueRequest(dip, packet, inIface);
      } else {
        CERR("forward IPv4 packet")
        forwardIPv4Packet(packet, inIface);
      }
    } catch (const std::runtime_error& error) {
      CERR("reply icmp network unreachable")
      replyIcmpNetworkUnreachable(packet, inIface);
    }
  }
}


void
SimpleRouter::processIncommingIcmp(const Buffer& packet, const std::string& inIface) 
{
  struct ethernet_hdr *pEther = (struct ethernet_hdr*)packet.data();
  struct ip_hdr * pIPv4 = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
  struct icmp_hdr *pICMP;
  try {
    pICMP = validateICMP(packet);
  } catch (std::exception& e) {
    CERR(e.what())
    return;
  } catch (...) {
    CERR("Unexpected exception")
    return;
  }
  if (pICMP->icmp_type != 8 || pICMP->icmp_code != 0) {
    CERR("not icmp request")
    return;
  }
  const auto routing_entry = m_routingTable.lookup(pIPv4->ip_src);
  const auto outIface = findIfaceByName(routing_entry.ifName);
  const auto arp_entry = m_arp.lookup(routing_entry.gw);
  DEBUG;
  if (arp_entry == nullptr) {
    CERR("Arp entry not found, queue ICMP echo reply")
    m_arp.queueRequest(routing_entry.gw, packet, inIface);
    return;
  }
  // send an Echo Reply:
  Buffer& reply = *(new Buffer(packet));
  struct ethernet_hdr *pReplyEther = (struct ethernet_hdr*)reply.data();
  struct ip_hdr *pReplyIPv4 = (struct ip_hdr*)((uint8_t*)pReplyEther + sizeof(struct ethernet_hdr)); 
  struct icmp_hdr *pReplyICMP = (struct icmp_hdr*)((uint8_t*)pReplyIPv4 + sizeof(struct ip_hdr));
  // prepare icmp header
  pReplyICMP->icmp_type = 0;
  pReplyICMP->icmp_code = 0;
  pReplyICMP->icmp_sum = 0;
  pReplyICMP->icmp_sum = cksum((uint8_t*)pReplyICMP, packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));
  // prepare ip header
  pReplyIPv4->ip_id = 0;
  pReplyIPv4->ip_src = pIPv4->ip_dst;
  pReplyIPv4->ip_dst = pIPv4->ip_src;
  pReplyIPv4->ip_sum = 0;
  pReplyIPv4->ip_ttl = 64;
  pReplyIPv4->ip_sum = cksum(pReplyIPv4, sizeof(struct ip_hdr));
  // prepare ethernet header
  memcpy(pReplyEther->ether_shost, pEther->ether_dhost, 6);
  memcpy(pReplyEther->ether_dhost, pEther->ether_shost, 6);
  sendPacket(reply, outIface->name);
}

void
SimpleRouter::processArpReply(const Buffer& packet) {
  struct arp_hdr *pArp = (struct arp_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
  // extract src IP and src MAC
  uint32_t ip = pArp->arp_sip;
  Buffer mac(pArp->arp_sha, pArp->arp_sha + 6);
  if (m_arp.lookup(ip) == nullptr) { 
    CERR("ARP reply, new entry: ")
    //print_addr_ip_int(ip);
    CERR(macToString(mac))
    auto arpRequest = m_arp.insertArpEntry(mac, ip);
    if (arpRequest == nullptr) {
      CERR("No queued request to remove")
    } else {
      CERR("Remove queued request")
      for (auto pendingPacket: arpRequest->packets) {
        handlePacket(pendingPacket.packet, pendingPacket.iface);
      }
      m_arp.removeRequest(arpRequest);
    }
  } else {
    CERR("ARP reply, arp entry already exists")
  }
}

void 
SimpleRouter::forwardIPv4Packet(const Buffer& packet, const std::string& inIface) 
{
  struct ip_hdr* pIPv4 = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
  uint32_t dip = pIPv4->ip_dst;
  const auto routing_entry = m_routingTable.lookup(dip);
  const auto arp_entry = m_arp.lookup(routing_entry.gw);
  if (arp_entry == nullptr) {
    CERR("Arp entry not found, queue IPv4 Packet to forward")
    m_arp.queueRequest(routing_entry.gw, packet, inIface);
    return;
  }
  // make a new packet, and send it via entry.ifName 
  Buffer forward = packet;
  struct ethernet_hdr *pForwardEther = (struct ethernet_hdr*)forward.data();
  struct ip_hdr *pForwardIPv4 = (struct ip_hdr*)((uint8_t*)forward.data() + sizeof(struct ethernet_hdr)); 
  const auto outIface = findIfaceByName(routing_entry.ifName);
  // prepare ip header
  pForwardIPv4->ip_sum = 0;
  pForwardIPv4->ip_ttl --; 
  pForwardIPv4->ip_sum = cksum(pForwardIPv4, sizeof(struct ip_hdr));
  // prepare ethernet header
  memcpy(pForwardEther->ether_shost, outIface->addr.data(), 6);
  memcpy(pForwardEther->ether_dhost, arp_entry->mac.data(), 6); 
  sendPacket(forward, routing_entry.ifName);
}

void SimpleRouter::sendArpReply(const Buffer& packet, const std::string& inIface) {
  Buffer& reply = *(new Buffer(packet));
  struct ethernet_hdr *pEther = (struct ethernet_hdr*)packet.data();
  struct arp_hdr * pARP = (struct arp_hdr*)((uint8_t*)pEther + sizeof(struct ethernet_hdr));
  struct ethernet_hdr *pReplyEther = (struct ethernet_hdr*)reply.data();
  struct arp_hdr *pReplyArp = (struct arp_hdr*)((uint8_t*)reply.data()+sizeof(struct ethernet_hdr));
  const Interface* iface = findIfaceByName(inIface);
  // set MAC dst and src
  memcpy(pReplyEther->ether_dhost, pEther->ether_shost, ETHER_ADDR_LEN);
  memcpy(pReplyEther->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
  pReplyArp->arp_op = htons(0x0002);
  // set arp MAC dst and src
  memcpy(pReplyArp->arp_tha, pARP->arp_sha, ETHER_ADDR_LEN);
  memcpy(pReplyArp->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
  // set arp IP dst and src
  pReplyArp->arp_tip = pARP->arp_sip;
  pReplyArp->arp_sip = pARP->arp_tip;
  sendPacket(reply, iface->name);
}

void 
SimpleRouter::replyIcmpPortUnreachable(const Buffer& packet, const std::string& inIface) 
{
  struct ethernet_hdr *pEther = (struct ethernet_hdr*)((uint8_t*)packet.data());
  struct ip_hdr *pIPv4 = (struct ip_hdr*)((uint8_t*)pEther + sizeof(struct ethernet_hdr));
  const auto routing_entry = m_routingTable.lookup(pIPv4->ip_src);
  const auto outIface = findIfaceByName(routing_entry.ifName);
  const auto arp_entry = m_arp.lookup(routing_entry.gw);
  CERR("routing entry: ")
  CERR(routing_entry)
  CERR("out iface: ")
  CERR(*outIface)
  if (arp_entry == nullptr) {
    CERR("Arp entry not found, queue ICMP Port Unreachable")
    m_arp.queueRequest(routing_entry.gw, packet, inIface);
    return;
  }
  Buffer& reply = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
  struct ethernet_hdr *pReplyEther = (struct ethernet_hdr*)((uint8_t*)reply.data());
  struct ip_hdr *pReplyIPv4 = (struct ip_hdr*)((uint8_t*)pReplyEther + sizeof(struct ethernet_hdr));
  struct icmp_t3_hdr *pReplyIcmpT3 = (struct icmp_t3_hdr*)((uint8_t*)pReplyIPv4 + sizeof(struct ip_hdr));
  memcpy(pReplyEther, pEther, sizeof(struct ethernet_hdr));
  memcpy(pReplyIPv4, pIPv4, sizeof(struct ip_hdr));
  // prepare ICMP
  pReplyIcmpT3->icmp_type = 3;
  pReplyIcmpT3->icmp_code = 3;
  pReplyIcmpT3->icmp_sum = 0; // ?
  pReplyIcmpT3->unused = 0; // ?
  pReplyIcmpT3->next_mtu = 0; // ?
  memcpy(pReplyIcmpT3->data, pIPv4, ICMP_DATA_SIZE);
  pReplyIcmpT3->icmp_sum = cksum(pReplyIcmpT3, sizeof(struct icmp_t3_hdr));
  // prepare IP
  pReplyIPv4->ip_id = 0;
  pReplyIPv4->ip_src = pIPv4->ip_dst;
  pReplyIPv4->ip_dst = pIPv4->ip_src;
  pReplyIPv4->ip_sum = 0;
  pReplyIPv4->ip_ttl = 64;
  pReplyIPv4->ip_p = ip_protocol_icmp;
  pReplyIPv4->ip_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
  pReplyIPv4->ip_sum = cksum(pReplyIPv4, sizeof(struct ip_hdr));
  // prepare ethernet header
  memcpy(pReplyEther->ether_shost, outIface->addr.data(), 6);
  memcpy(pReplyEther->ether_dhost, arp_entry->mac.data(), 6);
  //print_hdrs(reply);
  sendPacket(reply, outIface->name);
}

void 
SimpleRouter::replyIcmpTimeExceeded(const Buffer& packet, const std::string& inIface) 
{
  struct ethernet_hdr *pEther = (struct ethernet_hdr*)((uint8_t*)packet.data());
  struct ip_hdr *pIPv4 = (struct ip_hdr*)((uint8_t*)pEther + sizeof(struct ethernet_hdr));
  const auto routing_entry = m_routingTable.lookup(pIPv4->ip_src);
  const auto outIface = findIfaceByName(routing_entry.ifName);
  const auto arp_entry = m_arp.lookup(routing_entry.gw);
  if (arp_entry == nullptr) {
    CERR("Arp entry not found, queue ICMP Time Exceeded")
    m_arp.queueRequest(routing_entry.gw, packet, inIface);
    return;
  }
  Buffer& reply = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
  struct ethernet_hdr *pReplyEther = (struct ethernet_hdr*)((uint8_t*)reply.data());
  struct ip_hdr *pReplyIPv4 = (struct ip_hdr*)((uint8_t*)pReplyEther + sizeof(struct ethernet_hdr));
  struct icmp_t3_hdr *pReplyIcmpT3 = (struct icmp_t3_hdr*)((uint8_t*)pReplyIPv4 + sizeof(struct ip_hdr));
  //struct icmp_t3_hdr *pIcmp = (struct icmp_t3_hdr*)((uint8_t*)pIPv4 + sizeof(struct ip_hdr));
  memcpy(pReplyEther, pEther, sizeof(struct ethernet_hdr));
  memcpy(pReplyIPv4, pIPv4, sizeof(struct ip_hdr));
  // prepare ICMP
  pReplyIcmpT3->icmp_type = 11;
  pReplyIcmpT3->icmp_code = 0;
  pReplyIcmpT3->icmp_sum = 0; 
  pReplyIcmpT3->unused = 0; 
  pReplyIcmpT3->next_mtu = 0; 
  memcpy((uint8_t*)(pReplyIcmpT3->data), (uint8_t*)pIPv4, ICMP_DATA_SIZE);
  pReplyIcmpT3->icmp_sum = cksum(pReplyIcmpT3, sizeof(struct icmp_t3_hdr));
  // prepare IP
  pReplyIPv4->ip_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
  pReplyIPv4->ip_p = ip_protocol_icmp;
  pReplyIPv4->ip_id = 0;
  pReplyIPv4->ip_src = outIface->ip;
  pReplyIPv4->ip_dst = pIPv4->ip_src;
  pReplyIPv4->ip_sum = 0;
  pReplyIPv4->ip_ttl = 64;
  pReplyIPv4->ip_sum = cksum(pReplyIPv4, sizeof(struct ip_hdr));
  // prepare ethernet header
  memcpy(pReplyEther->ether_shost, outIface->addr.data(), 6);
  memcpy(pReplyEther->ether_dhost, arp_entry->mac.data(), 6);
  sendPacket(reply, outIface->name);
  //print_hdrs((uint8_t*)reply.data(), reply.size());
}

void 
SimpleRouter::replyIcmpNetworkUnreachable(const Buffer& packet, const std::string& inIface) 
{
  struct ethernet_hdr *pEther = (struct ethernet_hdr*)((uint8_t*)packet.data());
  struct ip_hdr *pIPv4 = (struct ip_hdr*)((uint8_t*)pEther + sizeof(struct ethernet_hdr));
  const auto routing_entry = m_routingTable.lookup(pIPv4->ip_dst);
  const auto outIface = findIfaceByName(routing_entry.ifName);
  const auto arp_entry = m_arp.lookup(routing_entry.gw);
  if (arp_entry == nullptr) {
    CERR("Arp entry not found, queue ICMP Network Unreachable")
    m_arp.queueRequest(routing_entry.gw, packet, inIface);
    return;
  }
  Buffer& reply = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
  struct ethernet_hdr *pReplyEther = (struct ethernet_hdr*)((uint8_t*)reply.data());
  struct ip_hdr *pReplyIPv4 = (struct ip_hdr*)((uint8_t*)pReplyEther + sizeof(struct ethernet_hdr));
  struct icmp_t3_hdr *pReplyIcmpT3 = (struct icmp_t3_hdr*)((uint8_t*)pReplyIPv4 + sizeof(struct ip_hdr));
  //struct icmp_t3_hdr *pIcmp = (struct icmp_t3_hdr*)((uint8_t*)pIPv4 + sizeof(struct ip_hdr));
  memcpy(pReplyEther, pEther, sizeof(struct ethernet_hdr));
  memcpy(pReplyIPv4, pIPv4, sizeof(struct ip_hdr));
  // prepare ICMP
  pReplyIcmpT3->icmp_type = 3;
  pReplyIcmpT3->icmp_code = 0;
  pReplyIcmpT3->icmp_sum = 0; 
  pReplyIcmpT3->unused = 0; 
  pReplyIcmpT3->next_mtu = 0; 
  memcpy(pReplyIcmpT3->data, pIPv4, ICMP_DATA_SIZE);
  pReplyIcmpT3->icmp_sum = cksum(pReplyIcmpT3, sizeof(struct icmp_t3_hdr));
  // prepare IP
  pReplyIPv4->ip_id = 0;
  pReplyIPv4->ip_src = pIPv4->ip_dst;
  pReplyIPv4->ip_dst = pIPv4->ip_src;
  pReplyIPv4->ip_sum = 0;
  pReplyIPv4->ip_ttl = 64;
  pReplyIPv4->ip_sum = cksum(pReplyIPv4, sizeof(struct ip_hdr));
  // prepare ethernet header
  
  memcpy(pReplyEther->ether_shost, outIface->addr.data(), 6);
  memcpy(pReplyEther->ether_dhost, arp_entry->mac.data(), 6);
  sendPacket(reply, outIface->name);
}

void 
SimpleRouter::sendArpRequest(uint32_t ip) {
  Buffer &request = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)));
  struct ethernet_hdr *pEther = (struct ethernet_hdr*)(request.data());
  struct arp_hdr *pArp = (struct arp_hdr*)((uint8_t*)pEther + sizeof(struct ethernet_hdr));
  // prepare Arp header
  pArp->arp_hrd = htons(0x0001);
  pArp->arp_pro = htons(0x0800);
  pArp->arp_hln = 0x06;
  pArp->arp_pln = 0x04;
  pArp->arp_op = htons(0x0001);
  const auto routing_entry = m_routingTable.lookup(ip);
  // debug
  CERR(routing_entry)
  const auto outIface = findIfaceByName(routing_entry.ifName);
  memcpy(pArp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
  pArp->arp_sip = outIface->ip;
  for (int i = 0; i < ETHER_ADDR_LEN; i++) { pArp->arp_tha[i] = 0xff;}
  pArp->arp_tip = ip;
  // prepare Ethernet header
  memcpy(pEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  for (int i = 0; i < ETHER_ADDR_LEN; i++) { pEther->ether_dhost[i] = 0xff;}
  pEther->ether_type = htons(0x0806);
  sendPacket(request, outIface->name);
}


} // namespace simple_router 
