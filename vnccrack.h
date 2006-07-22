/*
 *  (C) 2006 Jack Lloyd (lloyd@randombit.net)
 */

#include <string>
#include <fstream>
#include <exception>

class Exception : public std::exception
   {
   public:
      const char* what() const throw() { return msg.c_str(); }
      Exception(const std::string& m) : msg(m) {}
      virtual ~Exception() throw() {}
   private:
      const std::string msg;
   };

class Wordlist
   {
   public:
      bool more_p() const;
      std::string next();

      Wordlist(const std::string&);
   private:
      std::string next_line();

      std::ifstream in;
      std::string last;
   };
