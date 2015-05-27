ABOUT
=====

This is a simple client implementation of the CPNP protocol used by the
Canon Selphy CP-900 printer, and possibly others. I'm not aware of any
protocol spec being available, but it was pretty simple to reverse-
engineer.

The protocol is fairly similar to the BJNP protocol used by normal Canon
printers. I've peeked at http://sourceforge.net/projects/cups-bjnp/ here
and there for hints and ideas.


INSTALL & USAGE
===============

This should be pretty simple. Just build it, there are no special
dependencies other than a Go compiler, obviously.

See --help for available flags. You can use --printer_ip/_mac to specify the
printer to send your job to. By default, the tool will send a discovery
packet to 255.255.255.255 and send the job to whichever printer responds
first (and since regular non-photo printers speak a slightly different
protocol, that's often going to be just fine). If you're trying to send a
job to a printer not on your local network/broadcast domain, you can use
--printer_ip.

The program is pretty spammy at runtime, I haven't really tried cleaning
it up yet. Also, I haven't been able to use it much yet, so maybe it won't
work for you at all.


AUTHOR
======

Questions, complaints, suggestions and misc. fan-mail are welcome by
e-mail: wilmer@gaast.net .

I hope I'll manage to respond, but I'm not very good at e-mail these
days. :-(
