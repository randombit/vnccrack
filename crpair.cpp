/*
 *  (C) 2006 Jack Lloyd (lloyd@randombit.net)
 */

#include "vnccrack.h"
#include <cctype>

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

void hex_decode(unsigned char out[16], const char* in)
   {
   for(int j = 0; j != 32; j += 2)
      {
      unsigned char nibble1 = get_nibble(in[j]);
      unsigned char nibble2 = get_nibble(in[j+1]);
      out[j/2] = (nibble1 << 4) | nibble2;
      }
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

   hex_decode(challenge, hex_str);
   hex_decode(response, hex_str + 32);
   }
