/*
 *  (C) 2006 Jack Lloyd (lloyd@randombit.net)
 */

#include "vnccrack.h"
#include <cctype>
#include <fstream>
#include <iostream>

namespace {

unsigned char get_nibble(char hex)
   {
   if(std::isupper(hex))
      return (hex - 'A') + 10; // upper case
   else if(std::islower(hex))
      return (hex - 'a') + 10; // lower case
   else
      return (hex - '0'); // digit
   }

std::vector<unsigned char> hex_decode(const char* in, int in_len)
   {
   if(in_len % 2 != 0)
      throw Exception("Hex strings must have even length");

   std::vector<unsigned char> out(in_len / 2);

   for(int j = 0; j != in_len; j += 2)
      {
      unsigned char nibble1 = get_nibble(in[j]);
      unsigned char nibble2 = get_nibble(in[j+1]);
      out[j/2] = (nibble1 << 4) | nibble2;
      }

   return out;
   }

}

bool ChallengeResponse::is_solved() const
   {
   return !solution.empty();
   }

std::string ChallengeResponse::solution_is() const
   {
   return solution;
   }

void ChallengeResponse::test(const TrialPassword& pass)
   {
   if(is_solved())
      return;

   DES_key_schedule des_ks = pass.key_schedule();

   bool matched = true;

   for(int j = 0; j != 16 && matched; j += 8)
      {
      unsigned char temp[8];

      for(int k = 0; k != 8; k++)
         temp[k] = challenge[j+k];

      DES_ecb_encrypt(&temp, &temp, &des_ks, DES_ENCRYPT);      

      for(int k = 0; k != 8; k++)
         if(temp[k] != response[j+k])
            matched = false;
      }

   if(matched)
      solution = pass.password();
   }

ChallengeResponse::ChallengeResponse(const std::string& line)
   {
   std::string hex;
   for(std::size_t j = 0; j != line.size(); j++)
      if(std::isxdigit(line[j]))
         hex += line[j];

   if(hex.size() != 64)
      throw Exception("Bad C/R input line " + line);

   const char* hex_str = hex.c_str();

   challenge = hex_decode(hex_str, 32);
   response = hex_decode(hex_str + 32, 32);
   }

void ChallengeResponses::test(const TrialPassword& pass)
   {
   for(std::size_t j = 0; j != crpairs.size(); j++)
      {
      if(crpairs[j].is_solved())
         continue;

      crpairs[j].test(pass);

      if(crpairs[j].is_solved())
         std::cout << "FOUND: C/R pair " << j+1 << " password="
                   << pass.password() << std::endl;
      }
   }

ChallengeResponses::ChallengeResponses(const std::string& filename)
   {
   std::ifstream in(filename.c_str());
   if(!in)
      throw Exception("Couldn't open C/R pair file " + filename);

   while(in.good())
      {
      std::string line;
      std::getline(in, line);

      if(line == "")
         continue;

      ChallengeResponse cr(line);
      crpairs.push_back(cr);
      }

   if(crpairs.size() == 0)
      throw Exception("No challenge/response pairs found");
   }

int ChallengeResponses::count() const
   {
   return crpairs.size();
   }

bool ChallengeResponses::all_solved() const
   {
   for(std::size_t j = 0; j != crpairs.size(); j++)
      if(!crpairs[j].is_solved())
         return false;
   return true;
   }
