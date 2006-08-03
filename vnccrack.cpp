/*
 *  (C) 2003,2006 Jack Lloyd (lloyd@randombit.net)
 */

#include "vnccrack.h"
#include <iostream>

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
   const std::string progfile = argv[0];

   try
      {
      if(argc != 3)
         throw Exception("Usage: " + progfile + " wordlist crpairs");

      Wordlist wordlist(argv[1]);
      ChallengeResponses crs(argv[2]);

      std::cout << "Attempting cracking of " << crs.count()
                << " challenge/response pairs..." << std::endl;

      Cout_Report reporter;

      VNC_Cracker cracker(reporter, wordlist);
      cracker.crack(crs);
      }
   catch(std::exception& e)
      {
      std::cerr << e.what() << std::endl;
      return 1;
      }

   return 0;
   }
