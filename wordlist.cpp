/*
 *  (C) 2006 Jack Lloyd (lloyd@randombit.net)
 */

#include "vnccrack.h"
#include <iostream>
#include <fstream>

Wordlist::Wordlist(const std::string& file)
   {
   if(file == "-")
      {
      in = &std::cin;
      owns = false;
      }
   else
      {
      in = new std::ifstream(file.c_str());
      owns = true;
      }
   }

Wordlist::~Wordlist()
   {
   if(owns)
      delete in;
   }

bool Wordlist::has_more() const
   {
   return in->good() && !in->eof();
   }

std::string Wordlist::next_line()
   {
   if(!has_more())
      return "";

   std::string next;
   std::getline(*in, next);

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
