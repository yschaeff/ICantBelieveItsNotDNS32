# I Can't Believe it is not DNS 32! #

ICBIND32! Is an authoritative DNS server designed to run on the ESP32 chip. It
features AXFR and sustained query loads of over 2000 queries per second.

## History ##

Originally I authored ICBIND! -a DNS server running on the ESP8266 build upon
Micro Python- to get acquainted with the ESP8266 hardware and toolchain. While
this was a quite capable chip there where some limitation (mostly memory) I
needed to work around in order to get something that behaved somewhat like a
DNS server.

Now, with the release of the long awaited ESP32 I again needed a hello world
project to get to know this platform. Enter ICBIND32!. Since this chip has much
more memory available less stupid tricks are needed. But this isn't my day job
so nothing is stopping me from using stupid tricks. Yay!

## Features ##

- AXFR support
- A blinking LED
- No non-volatile storage required
- Multi threaded query processing
- Up to 2100 Queries per second over WiFi
- UDP _and_ TCP query handling

### Futures ###

- Notify processing, maybe add TSIG?
- IPv6 (This is a limitation in the LWIP framework, the version used by esp-idf
  doesn't support dual stack)
- EDNS0
- Followed by DNSSEC

## Installation ##

Assuming you have already set up the ESP-IDF and are able to compile the
example programs.

- Check out the git master branch
- run `make menuconfig` and take a look at the 'DNS Configuration' section to
  define where to get the zone data from and known WIFI access points.
- run 'make flash' with the ESP32 in upload mode.
- reset the ESP, additionally 'make monitor' to verify.
- Figure out its IP address (will be printed to the serial port) and send a
  query!

## Operation ##

Upon startup ICBIND32! will, after bringing up the network, request a zone
transfer from the configured master. Once received it will process the AXFR and
build up its database. From then on it is ready to serve queries.

