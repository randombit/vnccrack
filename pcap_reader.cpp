#include <iostream>
#include <string>
#include <stdexcept>
#include <sstream>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include <ctype.h>

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

      std::ostringstream os;

      os << inet_ntoa(ip_header->ip_src) << ':' << tcp->source;
      src_addr_str = os.str();

      os << inet_ntoa(ip_header->ip_dst) << ':' << tcp->dest;
      dest_addr_str = os.str();

      return true;  // sucessfully got a TCP packet of some kind (yay)
      }

   return false; // all out of bits
   }

int main()
   {
   try
      {
      Packet_Reader reader("vnc_auth.pcap");

      while(reader.kick())
         {
         std::string payload = reader.payload();

         if(payload.find("VNCAUTH_") != std::string::npos)
            printf("Saw VNCAUTH_ req from %s to %s\n",
                   reader.source_address().c_str(),
                   reader.destination_address().c_str());

         for(size_t j = 0; j != payload.size(); ++j)
            {
            if(isprint(payload[j]))
               printf("%c", payload[j]);
            else
               printf("\\%02X", payload[j]);
            }
         printf("\n");

         }

      }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }

   return 0;
   }
