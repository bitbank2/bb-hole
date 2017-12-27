bb-hole
<br>
Copyright (c) 2017 BitBank Software, Inc.<br>
Written by Larry Bank<br>
bitbank@pobox.com<br>
<br>
A DNS 'black hole' to block ads and unwanted sites from your local network.
The idea is that a relatively simple piece of software can catch the DNS
requests for your local network and filter them based on lists of sites
which you would like to block. This can be used to block advertisements and
unwanted/dangerous sites as well. This program listens on port 53 (DNS) for
domain name requests. It then compares the name to the blacklist and if present,
it redirects the request to the local (our) web server. If not present, the
request is forwarded to a trusted DNS server (e.g. Google). There are 2 ways
that the requests are forwarded:<br>
<br>
1) RAW sockets - A spoofed return address is placed in a RAW socket and the
   data is sent to a trusted DNS server. The server will route the response
   back to the original requestor instead of this program. This may not work
   on all Linux systems nor on all networks.<br>
<br>
2) Proxy - Each DNS request has a 16-bit transaction ID. This ID is stored in
   a table and the request is sent to the trusted DNS server. When the response
   comes back from the server, it's sent back to the original requestor based
   on the transaction ID. It's possible to have repeated (conflicting) IDs
   with enough people making requests on your network, but hopefully never
   happens.<br>
<br>
The other port that is monitored by this code is port 80 (HTTP). It waits for
redirected (blocked) requests and responds with placeholder images+scripts (you
can provide), or can generate a statistics report for display in a browser.<br>
<br>
I've also added code to display the statistics on a OLED display in real time.


