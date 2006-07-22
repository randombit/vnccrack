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
#include <openssl/des.h>

#include "vnccrack.h"

typedef unsigned char byte;

bool next_pass(Wordlist&, std::string&);
void try_pass(const std::string&, std::vector<byte*>&, std::vector<byte*>&);
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

   std::string password;
   while(1)
      {
      if(!next_pass(wordlist, password))
         break;
      try_pass(password, challenges, responses);
      }

   for(size_t j = 0; j != challenges.size(); j++)
      delete[] (challenges[j]);
   for(size_t j = 0; j != responses.size(); j++)
      delete[] (responses[j]);

   return 0;
   }

bool next_pass(Wordlist& wordlist, std::string& next)
   {
   if(!wordlist.more_p())
      return false;

   next = wordlist.next();
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

/* Flip the bits, so we can be compatible with VNC's whacked out method */
const byte FLIP_THE_BITS[256] = {
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

void try_pass(const std::string& pass, std::vector<byte*>& challenges,
              std::vector<byte*>& responses)
   {
   byte passx[8] = { 0 };
   for(size_t j = 0; j != pass.length() && j != 8; j++)
      passx[j] = FLIP_THE_BITS[(byte)pass[j]];

   DES_key_schedule des_ks;
   DES_set_key_unchecked(&passx, &des_ks);

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

      std::cout << "FOUND: C/R pair " << j+1 << " password=" << pass
                << std::endl;
      /* clear it out so we know we've already found the pass here */
      delete[] this_chal;
      delete[] this_resp;
      challenges[j] = 0;
      responses[j] = 0;
      }
   }
