/*
 *  (C) 2006 Jack Lloyd (lloyd@randombit.net)
 */

#ifndef VNC_CRACKER_H__
#define VNC_CRACKER_H__

#include <exception>
#include <string>
#include <vector>
#include <iosfwd>

#include <botan/des.h>

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
      const Botan::DES& des_obj() const { return des; }

      TrialPassword(const std::string&);
   private:
      Botan::DES des;
      std::string pass;
   };

class ChallengeResponse
   {
   public:
      bool is_solved() const { return !solution.empty(); }
      std::string solution_is() const { return solution; }
      std::string to_string() const { return id; }

      void test(const TrialPassword&);

      ChallengeResponse(const std::string& challenge,
                        const std::string& response,
                        const std::string& id);
   private:
      std::string id, challenge, response, solution;
   };

class ChallengeResponses
   {
   public:
      int count() const;
      bool all_solved() const;

      void add(const ChallengeResponse& cr) { crpairs.push_back(cr); }

      void test(const std::string&, class Report&);

      ChallengeResponses() {}
   private:
      std::vector<ChallengeResponse> crpairs;
   };

class Password_Source
   {
   public:
      virtual bool has_more() const = 0;
      virtual std::string next() = 0;
      virtual ~Password_Source() {}
   };

class Wordlist : public Password_Source
   {
   public:
      bool has_more() const;
      std::string next();

      Wordlist(const std::string&);
      ~Wordlist();
   private:
      std::string next_line();

      std::istream* in;
      bool owns;
      std::string last;
   };

class Report
   {
   public:
      virtual void solution(const ChallengeResponse&, const std::string&) = 0;
      virtual ~Report() {}
   };

class VNC_Cracker
   {
   public:
      void crack(ChallengeResponses&);

      VNC_Cracker(Report& r, Password_Source& s) :
         report(r), source(s) {}
   private:
      Report& report;
      Password_Source& source;
   };

#endif
