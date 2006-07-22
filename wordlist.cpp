/*
 *  (C) 2006 Jack Lloyd (lloyd@randombit.net)
 */

#include "vnccrack.h"

Wordlist::Wordlist(const std::string& file) : in(file.c_str())
   {
   if(!in)
      throw Exception("Couldn't open wordlist " + file);
   }

bool Wordlist::more_p() const
   {
   return in.good() && !in.eof();
   }

std::string Wordlist::next_line()
   {
   if(!more_p())
      return "";

   std::string next;
   std::getline(in, next);

   if(next.length() > 8)
      next = next.substr(0, 8); /* truncate to 8 chars, VNC's limit */
   }

std::string Wordlist::next()
   {
   std::string line = next_line();

   while(line == last)
      {
      printf("Skipping %s\n", line.c_str());
      line = next_line();
      }

   last = line;
   return line;
   }
