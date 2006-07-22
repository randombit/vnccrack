/*
 *  (C) 2003,2006 Jack Lloyd (lloyd@randombit.net)
 */

#include "vnccrack.h"
#include <iostream>

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

      while(wordlist.has_more() && !crs.all_solved())
         crs.test(wordlist.next());
      }
   catch(std::exception& e)
      {
      std::cerr << e.what() << std::endl;
      return 1;
      }

   return 0;
   }
