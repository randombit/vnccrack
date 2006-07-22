VNCcrack 1.0.0

Taking a VNC challenge and response (presumably sniffed), VNCcrack
will crack the password using a word list. It requires OpenSSL 0.9.7
(or later) and a C++ compiler.

Usage:

$ ./vnccrack [wordlist] [crpairs]

where [wordlist] is a file containing potential passwords, and
[crpairs] is a file containing one or more challenge-response pairs,
as 32 byte hex strings separated by a space, like so:

DEA9CE46919ADCE6EFA841EDB81EED4B 850D7FD22E76F0E6CC943BD71580AF49
6B2D76103F9F7EC4589B4FBE60A6721B CFB73EB526FA87FDF65BF1DDF99B924D
9EB777429696A68BCF161D0DD7D30DD4 6231F933D44AB5BF1E10A7A8A63AAED6
4BCD59BEA3660B1117A5AAF51882BD4B 7D969B71EC0D12B0A616667B35B1F592
64B6FA4ABBD0ADA3707293810D5B99F3 2C9A27BB5AC22D3EFF82FFFFFB355454
BD5C09D2985B441C4458DEC801695BCB CD4730BECBDDED78843FA63C4FD0C31E 
FA3E0A7EF51BC10243A5B18307ADC406 8A9398A4170EBBA90CCF6FC304F4A972 
[...]

Comments may be included, marked off with a '#' character. When
VNCcrack finds a solution, it will print the challenge/response pair
and the password solving it to stdout.
