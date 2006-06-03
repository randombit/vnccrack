VNCcrack 0.9.1
October 31, 2004

Taking a VNC challenge and response (presumably sniffed), VNCcrack will crack
the password using a word list. It requires OpenSSL 0.9.7 (or later) and a C++
compiler. Read doc/usage.txt for more information.

Why not just pound the VNC server with logins until a password works? First,
obviously, it's extremely slow. It's made even slower by VNC's password
cracking countermesures, which introduce delays after a few bad logins. Lastly,
even if you've got the time, someone is bound to notice the absolutely massive
number of bad login messages such an attack would produce.

On my 1.4 Ghz Athlon, VNCcrack can test between 300K and 650K passwords a
second, depending on how many pairs are being tested. It helps to have a really
big wordlist if you're using this seriously. The cracking speed is also
predicated on what version of OpenSSL you've got, and how well it was
compiled (ie, how optimized the DES code is for your system).
