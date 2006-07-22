/*
 *  (C) 2006 Jack Lloyd (lloyd@randombit.net)
 */

#ifndef VNC_CRACKER_H__
#define VNC_CRACKER_H__

#include <string>
#include <fstream>
#include <exception>
#include <vector>

#include <openssl/des.h>

class Exception : public std::exception
   {
   public:
      const char* what() const throw() { return msg.c_str(); }
      Exception(const std::string& m) : msg(m) {}
      virtual ~Exception() throw() {}
   private:
      const std::string msg;
   };

class TrialPassword
   {
   public:
      std::string password() const { return pass; }
      DES_key_schedule key_schedule() const { return ks; }

      TrialPassword(const std::string&);
   private:
      DES_key_schedule ks;
      std::string pass;
   };

class ChallengeResponse
   {
   public:
      bool is_solved() const;
      std::string solution_is() const;

      void test(const TrialPassword&);

      ChallengeResponse(const std::string&);
   private:
      std::vector<unsigned char> challenge, response;
      std::string solution;
   };

class Report
   {
   public:
      virtual void solution(const ChallengeResponse&, const std::string&) = 0;
      virtual ~Report() {}
   };

class ChallengeResponses
   {
   public:
      int count() const;
      bool all_solved() const;

      void test(const TrialPassword&, Report&);
      ChallengeResponses(const std::string&);
   private:
      std::vector<ChallengeResponse> crpairs;
   };

class Wordlist
   {
   public:
      bool has_more() const;
      TrialPassword next();

      Wordlist(const std::string&);
   private:
      std::string next_line();

      std::ifstream in;
      std::string last;
   };

#endif
