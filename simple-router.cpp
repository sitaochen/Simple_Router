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
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
/*
private:
  ArpCache m_arp;
  RoutingTable m_routingTable;
  std::set<Interface> m_ifaces;
  std::map<std::string, uint32_t> m_ifNameToIpMap;

  friend class Router;
  pox::PacketInjectorPrx m_pox;
*/

  /*
    step 1: validation of `packet`, make sure this is a valid ethernet packet that we expect
    1.1 length of ethernet frame is at least 14-byte
    1.2 type is either 0x0806 (ARP) or 0x0800 (IPv4), otherwise discard this packet
    1.3 dest MAC address is of `iface`, or is of broadcast address FF:FF:FF:FF:FF:FF
  */
  if (packet.size() < 14) { 
    std::cerr << "packet size too small" << std::endl; 
    return;
  }
  struct ethernet_hdr *pPacket = (struct ethernet_hdr*)packet.data();
  uint16_t type = ethertype((uint8_t*)pPacket);
  if (type != ethertype_arp && type != ethertype_ip) {
    std::cerr << "Neither ARP or IP packet received: Type=" << std::hex << unsigned(type) << std::endl;
    return;
  }
  if (0 == memcmp(pPacket->ether_dhost, iface->addr.data(), 6)) {
    std::cerr << "Dest MAC is to this router" << std::endl;
  } else {
    std::cerr << "Dest MAC is not this router" << std::endl;
    if ((packet[0] & packet[1] & packet[2] & packet[3] & packet[4] & packet[5]) == 0xff) {
      std::cerr << "Dest MAC is broadcast" << std::endl;
    } else {
      std::cerr << "Dest MAC is not broadcast address" << std::endl;
      std::cerr << "Dest MAC: " << macToString(packet) << std::endl;
      return ;
    } 
  } 
  /*
    dispatch ethernet payload
  */
  struct ip_hdr *pIPv4;
  struct arp_hdr *pARP;
  if (type == ethertype_arp) {
    /*
      step 2: validation of ARP pacekt
      2.1 length of ARP frame
      2.2 Hardware Type: 0x0001 (Ethernet)
      2.3 Protocol Type: 0x0800 (IPv4)
      2.4 Opcode: 1 (ARP request) 2 (ARP reply)
      2.5 HW addr len: number of octets in the specified hardware address. Ethernet has 6-octet addresses, so 0x06.
      2.6 Prot addr len: number of octets in the requested network address. IPv4 has 4-octet addresses, so 0x04.
    */
    if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)) {
      std::cerr << "Incorrect ARP size: " << packet.size()-sizeof(struct ethernet_hdr) << std::endl;
      return;
    }
    pARP = (struct arp_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
    if (ntohs(pARP->arp_hrd) != arp_hrd_ethernet) {
      std::cerr << "ARP hardware type is not ethernet: " << std::hex << unsigned(ntohs(pARP->arp_hrd)) << std::endl;
      return;
    }
    if (ntohs(pARP->arp_pro) != 0x0800) {
      std::cerr << "ARP protocol is not IPv4: " << std::hex << unsigned(ntohs(pARP->arp_pro)) << std::endl;
      return;
    }
    if (ntohs(pARP->arp_op) != 1 && ntohs(pARP->arp_op) != 2) {
      std::cerr << "ARP is neither request nor reply, opcode: " << std::hex << unsigned(ntohs(pARP->arp_op)) << std::endl;
      return;
    }
    if (pARP->arp_hln != 0x06) {
      std::cerr << "ARP hw addr len is not 6, hln: " << std::hex << pARP->arp_hln << std::endl;
      return;
    }
    if (pARP->arp_pln != 0x04) {
      std::cerr << "ARP request network addr len is not 4, hln: " << std::hex << pARP->arp_pln << std::endl;
      return;
    }
    /*
      process ARP request/reply  
    */
    if (ntohs(pARP->arp_op) == 1) {
      /*
        step 3: process ARP request
        3.1 properly respond to ARP requests for MAC address for the IP address of the corresponding network interface
        3.2 ignore other ARP request
      */
      if (ntohl(pARP->arp_tip) == iface->ip) {
        Buffer reply = packet;
        struct ethernet_hdr *ether = (struct ethernet_hdr*)reply.data();
        memcpy(ether->ether_dhost, pPacket->ether_shost, 6);
        memcpy(ether->ether_shost, pPacket->ether_dhost, 6);
        ether->ether_type = pPacket->ether_type;

        struct arp_hdr *arp_reply = (struct arp_hdr*)((uint8_t*)reply.data()+sizeof(struct ethernet_hdr));
        arp_reply->arp_op = htons(2);
        memcpy(arp_reply->arp_sha, iface->addr.data(), 6);
        arp_reply->arp_sip = htonl(iface->ip);
        memcpy(arp_reply->arp_tha, pARP->arp_sha, 6);
        arp_reply->arp_tip = pARP->arp_sip;

        sendPacket(reply, inIface);
      } else {
        std::cerr << "ARP request dest not to router: " << std::endl;
        print_addr_ip(*(struct in_addr*)&(pARP->arp_tip));
      }
    } else {
      /*
        step 3: process ARP reply
        3.1 record IP-MAC mapping information in ARP cache (Source IP/Source hardware address in the ARP reply)
        3.2 send out all corresponding enqueued packets, I implement this function in ArpCache::periodicCheckArpRequestsAndCacheEntries();
      */
      std::cerr << "ARP reply received" << std::endl;
      Buffer mac(pARP->arp_sha, pARP->arp_sha + 6);
      uint32_t ip = ntohl(pARP->arp_sip);
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
  } else {
    /*
      step 2: 
      2.1 When your router receives an IP packet to be forwarded to a next-hop IP address, it should check ARP cache if it contains the corresponding MAC address:
      2.2 If a valid entry found, the router should proceed with handling the IP packet
      2.3 Otherwise, the router should queue the received packet and start sending ARP request to discover the IP-MAC mapping.
    */
    if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr)) {
      std::cerr << "IP packet size too small" << std::endl;
      return;
    }
    pIPv4 = (struct ip_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
    /*
      2.4 For each incoming IPv4 packet, your router should verify its checksum and the minimum length of an IP packet
      2.5 Your router should classify datagrams into (1) destined to the router (to one of the IP addresses of the router), and (2) datagrams to be forwarded:
        For (1), if packet carries ICMP payload, it should be properly dispatched. Otherwise, discarded (a proper ICMP error response is NOT required for this project).
        For (2), your router should use the longest prefix match algorithm to find a next-hop IP address in the routing table and attempt to forward it there
      2.6 For each forwarded IPv4 packet, your router should correctly decrement TTL and recompute the checksum.
    */
    int ip_hdr_len = 4 * (pIPv4->ip_hl);
    if (packet.size() < sizeof(struct ethernet_hdr) + ip_hdr_len) {
      std::cerr << "IP packet size too small" << std::endl;
      return;
    }
    uint16_t checksum = cksum((uint8_t*)pIPv4, ip_hdr_len);
    if (checksum != 0) {
      std::cerr << "IP header checksum is not correct: " << std::hex << unsigned(checksum) << std::endl;
      return;
    }
    uint32_t dip = ntohl(pIPv4->ip_dst);
    const Interface* iface_dest = findIfaceByIp(dip);
    if (iface_dest != nullptr) {
      std::cerr << "IP packet to router interface" << std::endl;
    } else {
      const auto entry = m_routingTable.lookup(dip);
      // gateway vs dest
      // can a host send packets to itself?
      uint32_t dip = entry.dest;
      // make a new packet, and send it via entry.ifName 
    }
    return;
  }




  



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
