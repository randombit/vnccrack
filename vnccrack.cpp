/*
 *  (C) 2003,2006 Jack Lloyd (lloyd@randombit.net)
 *
 *   Todo:
 *     - Bit-sliced DES?
 */

#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdlib>
#include <cctype>

#include "vnccrack.h"

typedef unsigned char byte;

void try_pass(const TrialPassword&, std::vector<byte*>&, std::vector<byte*>&);
void decode_hex(const std::string&, byte*, byte*);

int main(int argc, char* argv[])
   {
   if(argc != 3)
      {
      std::cerr << "Usage: " << argv[0] << " wordlist crpairs" << std::endl;
      return 1;
      }

   Wordlist wordlist(argv[1]);

   std::ifstream crpairs(argv[2]);
   if(!crpairs)
      {
      std::cerr << "Couldn't open crpairs " << argv[2] << std::endl;
      return 1;
      }

   unsigned int crcount = 0;
   /*
      Storying the C/R pairs as a vector of byte* pointers is extremely ugly,
      but it's easy and efficient (and, moreover, it didn't require me to make
      too many changes when converting it from C).
   */
   std::vector<byte*> challenges;
   std::vector<byte*> responses;
   while(!crpairs.eof() && !crpairs.fail())
      {
      std::string line;

      std::getline(crpairs, line);

      if(line == "")
         continue;

      if(line.length() != 32 + 1 + 32)
         {
         std::cerr << "Bad input line: " << line << std::endl;
         std::exit(1);
         }

      crcount++;

      challenges.push_back(new byte[16]);
      responses.push_back(new byte[16]);

      decode_hex(line, challenges[crcount-1], responses[crcount-1]);
      }

   std::cout << "Loaded " << crcount << " challenge/response pairs"
             << std::endl;

   if(crcount == 0)
      {
      std::cerr << "No pairs found (!)" << std::endl;
      return 1;
      }

   std::cout << "Attempting crack: get some coffee?" << std::endl;

   while(wordlist.more_p())
      try_pass(wordlist.next(), challenges, responses);

   for(size_t j = 0; j != challenges.size(); j++)
      delete[] (challenges[j]);
   for(size_t j = 0; j != responses.size(); j++)
      delete[] (responses[j]);

   return 0;
   }

/* Assumes ASCII */
byte get_nibble(char hex)
   {
   if(std::isupper(hex))
      return (hex - 'A') + 10;
   else if(std::islower(hex))
      return (hex - 'a') + 10;
   else if(std::isdigit(hex))
      return (hex - '0');

   std::cerr << "Bad hex char " << hex << std::endl;
   std::exit(1);
   return 0; /* stupid compiler */
   }

void decode_hex(const std::string& line, byte* challenge, byte* response)
   {
   if(line.length() != 65)
      {
      std::cout << "CR line " << line << " isn't the right size" << std::endl;
      std::exit(1);
      }

   memset(challenge, 0, 16);
   memset(response, 0, 16);

   for(int j = 0; j != 32; j += 2)
      {
      byte nibble1 = 0, nibble2 = 0;
      nibble1 = get_nibble(line[j]);
      nibble2 = get_nibble(line[j+1]);
      challenge[j/2] = (nibble1 << 4) | nibble2;
      }

   for(int j = 33; j != 65; j += 2)
      {
      byte nibble1 = 0, nibble2 = 0;
      nibble1 = get_nibble(line[j]);
      nibble2 = get_nibble(line[j+1]);
      response[(j-1-32)/2] = (nibble1 << 4) | nibble2;
      }
   }

void try_pass(const TrialPassword& pass, std::vector<byte*>& challenges,
              std::vector<byte*>& responses)
   {
   DES_key_schedule des_ks = pass.key_schedule();

   const size_t how_many = challenges.size();

   for(size_t j = 0; j != how_many; j++)
      {
      const byte* this_chal = challenges[j];
      const byte* this_resp = responses[j];

      if(this_chal == 0 || this_resp == 0)
         continue;

      byte chal[8];

      memcpy(chal, this_chal, 8);
      DES_ecb_encrypt(&chal, &chal, &des_ks, DES_ENCRYPT);
      if(memcmp(chal, this_resp, 8))
         continue; /* not this one */

      memcpy(chal, this_chal + 8, 8);
      DES_ecb_encrypt(&chal, &chal, &des_ks, DES_ENCRYPT);
      if(memcmp(chal, this_resp + 8, 8))
         continue; /* not this one (unlikely) */

      std::cout << "FOUND: C/R pair " << j+1 << " password="
                << pass.password() << std::endl;

      /* clear it out so we know we've already found the pass here */
      delete[] this_chal;
      delete[] this_resp;
      challenges[j] = 0;
      responses[j] = 0;
      }
   }
