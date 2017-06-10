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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

void 
ArpCache::handle_arpreq(std::shared_ptr<ArpRequest>& request) {
  time_point now = steady_clock::now();
  if (now - request->timeSent <= seconds(1)) { return; }
  if (request->nTimesSent == 5) { // 5 times and timeout
    for (auto & pendingPacket : request->packets) {
      
      std::cerr << "5 tries and 30s timeout, send Icmp host Unreachable" << std::endl;
      replyIcmpHostUnreachable(pendingPacket.packet, pendingPacket.iface);
    }
    //m_arpRequests.remove(request);
    //removeRequest(request);

    return;  
  }
  std::cerr << "handle_arpreq, send arp request";
  print_addr_ip_int(request->ip);
  
  m_router.sendArpRequest(request->ip);
  request->nTimesSent ++;
  request->timeSent = now;
}

// I cannot queue ICMP Host Unreachable, because lock issue
void ArpCache::replyIcmpHostUnreachable(Buffer& packet, std::string& iface) {
  // if queued packet itself is an ICMP Host Unreachable, return.
  // only IP packet are queued, there is no chance that arp packet are not queued.
  struct ethernet_hdr *pEther = (struct ethernet_hdr*)((uint8_t*)packet.data());
  struct ip_hdr *pIPv4 = (struct ip_hdr*)((uint8_t*)pEther + sizeof(struct ethernet_hdr));
  std::shared_ptr<ArpEntry> arp_entry;
  
  Buffer& reply = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
  struct ethernet_hdr *pReplyEther = (struct ethernet_hdr*)((uint8_t*)reply.data());
  struct ip_hdr *pReplyIPv4 = (struct ip_hdr*)((uint8_t*)pReplyEther + sizeof(struct ethernet_hdr));
  struct icmp_t3_hdr *pReplyIcmpT3 = (struct icmp_t3_hdr*)((uint8_t*)pReplyIPv4 + sizeof(struct ip_hdr));
  //struct icmp_t3_hdr *pIcmp = (struct icmp_t3_hdr*)((uint8_t*)pIPv4 + sizeof(struct ip_hdr));
  memcpy(pReplyEther, pEther, sizeof(struct ethernet_hdr));
  memcpy(pReplyIPv4, pIPv4, sizeof(struct ip_hdr));
  // prepare ICMP
  pReplyIcmpT3->icmp_type = 3;
  pReplyIcmpT3->icmp_code = 1;
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
  pReplyIPv4->ip_p = ip_protocol_icmp;
  pReplyIPv4->ip_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
  pReplyIPv4->ip_sum = cksum(pReplyIPv4, sizeof(struct ip_hdr));
  // prepare ethernet header
  const auto routing_entry = m_router.getRoutingTable().lookup(pIPv4->ip_dst);
  const auto outIface = m_router.findIfaceByName(routing_entry.ifName);
  memcpy(pReplyEther->ether_shost, outIface->addr.data(), 6);
  
  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == pIPv4->ip_src) {
      arp_entry = entry;
      break;
    }
  }
  if (!arp_entry) {
    std::cerr << "Arp entry not found, drop ICMP Host Unreachable" << std::endl;
    return;
  }
  memcpy(pReplyEther->ether_dhost, arp_entry->mac.data(), 6);
  m_router.sendPacket(reply, outIface->name);
  DEBUG;
}



//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // check request
  std::vector<std::list<std::shared_ptr<ArpRequest>>::iterator> invalidRequests;
  for (auto it = m_arpRequests.begin(); it != m_arpRequests.end(); ++it) {
    if ((*it)->nTimesSent == 5) {
      invalidRequests.push_back(it);
    }
  }
  for (auto it: invalidRequests) {
    m_arpRequests.remove(*it);
  }

  // FILL THIS IN
  for (auto p : m_arpRequests) {
    handle_arpreq(p);
  }
  

  // check cache entries
  std::vector<std::list<std::shared_ptr<ArpEntry>>::iterator> invalidEntries;
  for (auto it = m_cacheEntries.begin(); it != m_cacheEntries.end(); ++it) {
    if (!(*it)->isValid) {
      invalidEntries.push_back(it);
    }
  }
  for (auto it: invalidEntries) {
    m_cacheEntries.erase(it);
  }


}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  DEBUG;
  std::lock_guard<std::mutex> lock(m_mutex);
  DEBUG;
  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::cerr << "queued ip: ";
  print_addr_ip_int(ip);
  DEBUG;
  std::lock_guard<std::mutex> lock(m_mutex);
  DEBUG;
  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
    //print_hdrs(packet);
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  DEBUG;
  std::lock_guard<std::mutex> lock(m_mutex);
  DEBUG;
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  DEBUG;
  std::lock_guard<std::mutex> lock(m_mutex);
  DEBUG;
  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  DEBUG;
  std::lock_guard<std::mutex> lock(m_mutex);
  DEBUG;
  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      //DEBUG;
      std::lock_guard<std::mutex> lock(m_mutex);
      //DEBUG;
      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  DEBUG;
  std::lock_guard<std::mutex> lock(cache.m_mutex);
  DEBUG;
  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
