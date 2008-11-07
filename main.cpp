/*
  (C) 2008 Jack Lloyd <lloyd@randombit.net>
*/
#include <iostream>
#include <string>
#include <stdexcept>
#include <sstream>
#include <fstream>
#include <cctype>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "vnccrack.h"

#include <botan/botan.h>

class Packet_Reader
   {
   public:
      Packet_Reader(const std::string& filename);
      ~Packet_Reader();

      bool kick();

      std::string payload() const { return payload_str; }
      std::string destination_address() const { return dest_addr_str; }
      std::string source_address() const { return src_addr_str; }

   private:
      char pcap_errbuf[PCAP_ERRBUF_SIZE];
      pcap_t* pcap_handle;

      std::string payload_str, dest_addr_str, src_addr_str;
   };

Packet_Reader::Packet_Reader(const std::string& filename)
   {
   pcap_handle = pcap_open_offline(filename.c_str(), pcap_errbuf);

   if(!pcap_handle)
      throw std::runtime_error("Could not read pcap file " + std::string(pcap_errbuf));
   }

Packet_Reader::~Packet_Reader()
   {
   if(pcap_handle)
      {
      pcap_close(pcap_handle);
      pcap_handle = 0;
      }
   }

bool Packet_Reader::kick()
   {
   pcap_pkthdr header;

   payload_str = dest_addr_str = src_addr_str = ""; // reset

   while(const u_char* packet = pcap_next(pcap_handle, &header))
      {
      if(header.len < sizeof(struct ether_header))
         continue;

      const struct ether_header* eptr = reinterpret_cast<const struct ether_header*>(packet);

      if(ntohs(eptr->ether_type) != ETHERTYPE_IP)
         continue;

      if(header.len < sizeof(struct ether_header) + sizeof(struct ip))
         continue;

      const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + sizeof(ether_header));

      size_t size_ip = 4 * ip_header->ip_hl;
      if(size_ip < 20)
         continue; // bogus IP header

      if(header.len < sizeof(struct ether_header) + size_ip + sizeof(tcphdr))
         continue;

      const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + sizeof(ether_header) + size_ip);

      size_t size_tcp = tcp->doff * 4;

      if(size_tcp < 20)
         continue; // bongus TCP header

      const u_char* payload_buf = packet + sizeof(ether_header) + size_ip + size_tcp;
      const size_t payload_len = header.len - (sizeof(ether_header) + size_ip + size_tcp);

      payload_str = std::string(reinterpret_cast<const char*>(payload_buf), payload_len);

      std::ostringstream os1;
      os1 << inet_ntoa(ip_header->ip_src) << ':' << tcp->source;
      src_addr_str = os1.str();

      std::ostringstream os2;
      os2 << inet_ntoa(ip_header->ip_dst) << ':' << tcp->dest;
      dest_addr_str = os2.str();

      return true;  // sucessfully got a TCP packet of some kind (yay)
      }

   return false; // all out of bits
   }

class VNC_Auth_Reader
   {
   public:
      VNC_Auth_Reader(const std::string& filename) : reader(filename) {}

      bool find_next(std::string& destination_address_out,
                     std::string& source_address_out,
                     std::string& challenge_out,
                     std::string& response_out);

   private:
      Packet_Reader reader;
   };

bool VNC_Auth_Reader::find_next(std::string& destination_address_out,
                                std::string& source_address_out,
                                std::string& challenge_out,
                                std::string& response_out)
   {
   while(reader.kick())
      {
      const std::string payload = reader.payload();

      // This could be a lot smarter. It would be nice in particular
      // to handle malformed streams and concurrent handshakes.
      if(payload.find("VNCAUTH_") != std::string::npos)
         {
         const std::string from = reader.source_address();
         const std::string to = reader.destination_address();

         std::string challenge, response;

#if 0
         printf("Saw VNCAUTH_ from %s to %s, searching...\n", from.c_str(), to.c_str());
#endif

         while(reader.kick()) // find the challene
            {
#if 0
            printf("Found new packet len %d from %s to %s\n",
                   reader.payload().length(),
                   reader.source_address().c_str(),
                   reader.destination_address().c_str());
#endif

            if(from == reader.source_address() &&
               to == reader.destination_address() &&
               reader.payload().size() == 16)
               {
               challenge = reader.payload();
               break;
               }
            }

         while(reader.kick()) // now find response
            {
#if 0
            printf("Found new packet len %d from %s to %s\n",
                   reader.payload().length(),
                   reader.source_address().c_str(),
                   reader.destination_address().c_str());
#endif

            if(to == reader.source_address() &&
               from == reader.destination_address() &&
               reader.payload().size() == 16)
               {
               response = reader.payload();
               break;
               }
            }

         if(challenge != "" && response != "")
            {
            challenge_out = challenge;
            response_out = response;
            destination_address_out = to;
            source_address_out = from;
            return true;
            }
         }
      }

   return false; // out of gas
   }

std::ostream& operator<<(std::ostream& out, const ChallengeResponse& cr)
   {
   out << cr.to_string();
   return out;
   }

class Cout_Report : public Report
   {
   public:
      void solution(const ChallengeResponse& cr, const std::string& pass)
         {
         std::cout << "Found: " << cr << " -> " << pass << "\n";
         }
   };

int main(int argc, char* argv[])
   {
   try
      {
      if(argc != 3)
         {
         std::cerr << "Usage: " << argv[0] << " <pcapfile> <wordlist>\n";
         return 1;
         }

      Botan::LibraryInitializer init;

      VNC_Auth_Reader read(argv[1]);
      Wordlist wordlist(argv[2]);
      ChallengeResponses crs;

      std::string to, from, challenge, response;

      while(read.find_next(to, from, challenge, response))
         {
         crs.add(ChallengeResponse(challenge, response, "To " + to + " from " + from));
         }

      Cout_Report reporter;

      VNC_Cracker cracker(reporter, wordlist);
      cracker.crack(crs);
      }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }

   return 0;
   }
