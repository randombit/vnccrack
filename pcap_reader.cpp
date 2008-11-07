#include <iostream>
#include <string>
#include <stdexcept>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


int main()
   {
   try
      {
      char pcap_errbuf[PCAP_ERRBUF_SIZE];
      pcap_t* pcap = pcap_open_offline("vnc_auth.pcap", pcap_errbuf);

      if(!pcap)
         throw std::runtime_error("Could not read pcap file " + std::string(pcap_errbuf));

      pcap_pkthdr header;

      while(const u_char* packet = pcap_next(pcap, &header))
         {
         const struct ether_header* eptr = reinterpret_cast<const struct ether_header*>(packet);

         if(ntohs(eptr->ether_type) != ETHERTYPE_IP)
            continue;

         const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + sizeof(ether_header));

         printf("Got something IP\n");

         size_t size_ip = ip_header->tot_len;
         if(size_ip < 20)
            continue; // bogus IP header

         const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + sizeof(ether_header) + size_ip);

         printf("Got something TCP\n");

         size_t size_tcp = 20;//TH_OFF(tcp)*4;

         if(size_tcp < 20)
            continue; // bongus TCP header

         const u_char* payload = packet + sizeof(ether_header) + size_ip + size_tcp;
         const size_t payload_len = header.len - (sizeof(ether_header) + size_ip + size_tcp);

         printf("%d\n", payload_len);

         }


      pcap_close(pcap);
      }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }

   return 0;
   }
