/*
 *  (C) 2003,2006 Jack Lloyd (lloyd@randombit.net)
 */

#include "vnccrack.h"
#include <iostream>

int main(int argc, char* argv[])
   {
   if(argc != 3)
      {
      std::cerr << "Usage: " << argv[0] << " wordlist crpairs" << std::endl;
      return 1;
      }

   Wordlist wordlist(argv[1]);

   ChallengeResponses crs(argv[2]);

   std::cout << "Loaded " << crs.count() << " challenge/response pairs"
             << std::endl;

   if(crs.count() == 0)
      {
      std::cerr << "No challenge/response pairs found, quitting" << std::endl;
      return 1;
      }

   std::cout << "Attempting crack: get some coffee?" << std::endl;

   while(wordlist.has_more() && !crs.all_solved())
      crs.test(wordlist.next());

   return 0;
   }
