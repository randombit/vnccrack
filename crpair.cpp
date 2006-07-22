/*
 *  (C) 2006 Jack Lloyd (lloyd@randombit.net)
 */

#include "vnccrack.h"

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
   }
