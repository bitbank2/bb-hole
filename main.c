//
// BB-Hole
//
// Copyright (c) 2017 BitBank Software, Inc.
// Written by Larry Bank
//
// Project started 10/21/2017
//
// A program to act as a DNS middle-man to filter
// DNS requests to blacklisted sites and replace them
// with our own address to serve fake web pages and images.
// The idea for the project (besides a useful learning experience)
// is to be a single-module (aka simple) example of a DNS and HTTP
// server that can run without messing up the configuration of your
// machine.
//
// It can act as a proxy to ferry requests back and forth
// between a requestor and a DNS server, or it can use RAW
// sockets to 'spoof' the return address and forward the
// request so that the response comes back to the requestor.
// The RAW method isn't compatible with MacOS. It also causes nslookup
// to complain, but web browsers don't seem to mind. The intended
// target system for this program is a small ARM SBC running
// Debian/Ubuntu Linux.
//
// Instead of using a HASH with a dynamic structure, I created a simpler
// static HASH which reduces the first 3 letters of the domain name into an
// 18-bit number with a quick lookup table to see if an entry is valid. This allows
// the code to run forever and never fragment memory because it allocates
// everything it needs when it starts and never needs to change the buffers.
// The amount of memory needed is still trivial (unless you want to run this
// on an ESP32).
//
// The web server component can provide 3 types of output:
// 1) A status report. To see this, enter http://<your address>/report.html
// 2) A fake HTML response for a blacklisted site - right now it's "Site Blocked!"
// 3) An image response for a blacklisted site's script request (e.g. sends back a small png/jpeg/gif).
// My intent is to fool sites into thinking that their ads have been served instead
// of timing out or blocking the script from running. This doesn't work yet, but
// I'm still experimenting with it.
//

// Uncomment this if you want the status output to be displayed on a small
// I2C OLED 0.96" display (with use of my oled_96 support library)
//#define SHOW_STATS_OLED
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include "pil_io.h"
#ifdef SHOW_STATS_OLED
#include <oled96.h>
#endif // SHOW_STATS_OLED

#define MAX_STRING 256
#define MAX_DNS 1024
#define MAX_HTTP 2048

#define THREE_SIZE 64*64*64
int FindMatch(unsigned char *);
static uint32_t u32MyAddr, u32DNS;
static int iDNSRequests = 0; // number of DNS requests
static int iHTTPRequests = 0;
static int iBlocked = 0; // number of requests blocked
static int bRunning;
static int server_sock, listen_sock;
static int bVerbose = 0;
static int bStats = 0;
static int bRAW = 0;

enum {
	RESPONSE_HTML=0,
	RESPONSE_INDEX,
	RESPONSE_REPORT,
	RESPONSE_GIF,
	RESPONSE_PNG,
	RESPONSE_JPG,
    RESPONSE_JSCRIPT
};

char *szTypes[] = {"Unknown","HTML","root page","report","gif","png","jpeg","javascript"};

// Simple javascript to send in response to ad requests
static const char *pJavaScript = "document.write('<p>Ad blocked by bb-hole!</p>');";

// 96 bit (12 bytes) pseudo eader needed for udp header checksum calculation
struct pseudo_header
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t udp_length;
};
//
// Translate 8-bit characters into 6-bit values to make text matching
// case insensitive and faster (aka my static HASH)
//
unsigned char ucCharTranslate[] = {
00,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63, // 0-31 non printable characters
1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, // 32-47 arbitrary order, just need to be unique for valid chars
17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32, // 48-63
33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48, // 64-79 - same values as the lower case
49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,63, // 80-95
63,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48, // 96-111 - lower case matches upper case
49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,63, // 112-127
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63, // 128-255 are invalid
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,
63,63,63,63,63,63,63,63,63,63,63,63,63,63,63,63
};
static int iListSize; // number of entries in the list
static uint32_t *pOffsets = NULL; // offsets in main character buffer to start of each line
static unsigned char *pListData = NULL; // holds the actual text data
static uint32_t *pListHeads = NULL; // 64x64x64 256K 3-letter list head pointers
static uint8_t *pListLens = NULL; // 64x64x64 3-letter list lengths
static uint32_t *pTransIDs; // DEBUG - temporary transaction id list for proxy
static uint16_t *pPortIDs; // DEBUG - port numbers
static uint8_t *pGIF, *pJPEG, *pPNG; // fake images to serve blocked requests
static int iGIFSize, iJPEGSize, iPNGSize, iJavaScriptSize;

//
// 16-bit checksum calculation for ip/udp headers
//
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
} /* csum() */

//
// Get our own IP address to display
//
int GetIPAddress(char *interface, char *address)
{   
    struct ifaddrs *ifaddr, *ifa;
    int s;
    char host[NI_MAXHOST];
    
    if (getifaddrs(&ifaddr) == -1)
    {   
        printf("getifaddrs() returned -1\n");
        return -1;
    }

    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {   
        if (ifa->ifa_addr == NULL)
            continue;
        
        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

//      printf("network name = %s\n", ifa->ifa_name);
        
        if((memcmp(ifa->ifa_name,"wl", 2)==0 || memcmp(ifa->ifa_name,"en0",3) == 0 || memcmp(ifa->ifa_name,"eth", 3)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {   
            if (s != 0)
            {   
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }
            strcpy(interface,ifa->ifa_name);
            strcpy(address, host);
        }
    }
    freeifaddrs(ifaddr);
    return 0;
} /* GetIPAddress() */

//
// DEBUG function to dump memory as hex/ascii
//
void DumpData(unsigned char *s, int iLen)
{
int i, j;
	for (i=0; i<iLen; i+=8)
	{
		for (j=i; j<iLen && j<i+8; j++)
		{
			printf("%02x,", s[j]);
		}
		for (j=i; j<iLen && j<i+8; j++)
		{
			printf("%c",s[j]);
		}
		printf("\n");
	}
} /* DumpData() */

//
//  Returns the relative time in milliseconds
//
int MilliTime()
{
int iTime;
struct timespec res;

    clock_gettime(CLOCK_MONOTONIC, &res);
    iTime = 1000*res.tv_sec + res.tv_nsec/1000000;

    return iTime;
} /* MilliTime() */

//
// ShowHelp
//
// Display the help info when incorrect or no command line parameters are passed
//
void ShowHelp(void)
{
    printf(
	"bb-hole Copyright(c) 2017 BitBank Software, inc.\n"
    "written by Larry Bank\n"
	"A DNS ad/malware blocker\n\n"
    "bb-hole <options> list1 <list2> ... <listN>\n"
           "valid options:\n\n"
           "--verbose       show all DNS/HTTP activity\n"
           "--dns <server>  specify the real DNS server (defaults to 8.8.8.8)\n"
           "--stats         periodically display stats to TTY\n"
           "--raw           use RAW packet routing (defaults to proxy)\n"
    );
} /* ShowHelp() */

//
// Get the domain name from a DNS request packet
//
// We purposely truncate the name to the last 2 or 3 parts (w/country code)
// e.g. something.else.bad.com comes out as bad.com
// This makes an assumption that a site which we want
// blacklisted doesn't have anything useful to offer
// on its other sub-domains.
//
static int GetDomain(char *dest, char *src, int iLen)
{
int i=0; // current source offset
int j=1; // current segment length
int k = 0; // destination offset
int q;
int iMaxParts;
int iParts = 0;

	while (i < iLen && j)
	{
		j = src[i++]; // next segment length
		if (j && j < iLen-i)
		{
			iParts++; // how many sections of the name
			for(q=0; q<j; q++)
			{
				dest[k++] = src[i++];
			}
			dest[k++] = '.';
		}
	}
	if (k) dest[k-1] = '\0';
	if (iParts >= 3) // we just want the root domain
	{
		j = strlen(dest);
		iParts = 0; // number of dots found
		iMaxParts = 2;
		if (dest[k-4] == '.') // last part is probably a country
			iMaxParts = 3;
		while (j > 0 && iParts < iMaxParts)
		{
			if (dest[j] == '.') iParts++;
			j--;
		}
		strcpy(dest, &dest[j+2]); // capture the part we want
	}
    return i; // length of the name data + terminator
} /* GetDomain() */

//
// Write a 32-bit value in little endian order
//
// Necessary for avoiding memory alignment exceptions
// on systems which have strict requirements (e.g. old ARM CPUs)
//
static void Put32(char *pDest, int *i, uint32_t u32)
{
unsigned char *d = (unsigned char *)&pDest[*i];

	*d++ = (unsigned char)u32;
	*d++ = (unsigned char)(u32 >> 8);
	*d++ = (unsigned char)(u32 >> 16);
	*d++ = (unsigned char)(u32 >> 24);
	*i += 4;
} /* Put32() */

//
// Write a 16-bit value in little endian order
//
// Necessary for avoiding memory alignment exceptions
// on systems which have strict requirements (e.g. old ARM CPUs)
//
static void Put16(char *pDest, int *i, uint16_t u16)
{
    unsigned char *d = (unsigned char *)&pDest[*i];
    
    *d++ = (unsigned char)u16;
    *d++ = (unsigned char)(u16 >> 8);
    *i += 2;
} /* Put16() */

//
// Listen for DNS requests and forward or proxy them
// to a trusted DNS server if they don't match any
// names in our blacklist
//
void * DNS_Thread(void *unused)
{
    struct sockaddr_in addr, addrfrom, fwaddr;
    char buffer[MAX_DNS];
    char szDomain[MAX_STRING];
    int forward_sock, rc, iOrigLen, iNameLen;
    uint16_t u16Trans, u16Flags, *pu16;
    socklen_t addrLen = sizeof(struct sockaddr_in);
    
    pu16 = (uint16_t *)buffer;
    listen_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (bRAW)
        forward_sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW); //UDP);
    else
        forward_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_sock != -1 && forward_sock != -1)
    {
        //	printf("socket = %d\n", sock);
        rc = 1; // YES
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(rc)) == -1)
        {
            printf("Error setting listening sock option re-use address\n");
        }
#ifndef __MACH__
	if (bRAW && setsockopt(forward_sock, IPPROTO_IP, IP_HDRINCL, &rc, sizeof(rc)) < 0)
	{
		printf("Error setting raw socket option IP_HDRINCL\n");
	}
#endif
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53); // port address of DNS
        addr.sin_addr.s_addr = INADDR_ANY;
    
        /* bind to address and port */
        if (0 != bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)))
        {
            printf("Error binding listening socket = %d\n", errno);
	    return NULL;
        }

        memset(&fwaddr, 0, sizeof(fwaddr));
        fwaddr.sin_family = AF_INET;
        fwaddr.sin_port = htons(53);
        fwaddr.sin_addr.s_addr = u32DNS; // trusted DNS server
        
        while (bRunning)
        {
	   addrLen = sizeof(struct sockaddr_in);
	    rc = recvfrom(listen_sock, buffer, MAX_DNS, 0, (struct sockaddr *)&addrfrom, &addrLen);
            if (rc != 0 && rc != -1)
            {
                iOrigLen = rc;
		u16Trans = pu16[0]; // transaction ID
//                printf("Received %d bytes\n", rc);
//		printf("addrlen = %d, addrdata...\n", addrLen);
//		DumpData(&addrfrom, addrLen);
//                printf("Received from addr: %08x, family = %d, trans ID=%04x, port %04x\n", addrfrom.sin_addr.s_addr, addrfrom.sin_family, u16Trans, htons(addrfrom.sin_port));
                //DumpData((unsigned char *)buffer, rc);
                u16Flags = pu16[1]; // query flags
                if ((u16Flags & 0xf8) == 0) // query
                {
		    int bBlocked;
		    pTransIDs[u16Trans] = addrfrom.sin_addr.s_addr; // store return address for proxy
		    pPortIDs[u16Trans] = addrfrom.sin_port;
		    iDNSRequests++; // new DNS request
                    iNameLen = GetDomain(szDomain, &buffer[12], rc-12);
                    bBlocked = FindMatch((unsigned char *)szDomain); // found in our blacklist
                    if (bVerbose)
                        printf("DNS Request, domain = %s, %s\n", szDomain, (bBlocked) ? "Blocked!":"Forwarded");
		    if (bBlocked)
                    {
                        int i;
			iBlocked++; // new blocked request
                        //printf("Found match in blacklist\n");
                        // respond with our address
                        pu16[1] = 0x8081; // response flags (assumes little-endian)
                        pu16[2] = 0x100; // questions = 1
                        pu16[3] = 0x200; // answer RRs = 2
                        pu16[4] = 0; // authority RRs = 0
                        pu16[5] = 0; // additional RRs = 0
                        i = 12; // leave original query in response
                        i += iNameLen; // skip the original query name
                        i += 4; // skip Type (A) and class (IN)
                        buffer[i++] = 0xc0; // address
                        buffer[i++] = 0x0c; // offset 12
                        buffer[i++] = 0; // type 5 (CNAME)
                        buffer[i++] = 5;
                        buffer[i++] = 0;
                        buffer[i++] = 1; // CLASS
                        buffer[i++] = 0; // 4-byte TTL time to live
                        buffer[i++] = 5;
                        buffer[i++] = 0x28;
                        buffer[i++] = 0x39;
                        buffer[i++] = 0; // 16-bit length
                        buffer[i++] = iNameLen;
                        memcpy(&buffer[i], &buffer[12], iNameLen); // copy name again
                        i += iNameLen;
                        buffer[i++] = 0xc0; // address
                        buffer[i++] = 0x0c; // offset 12
                        buffer[i++] = 0; // type A (host address
                        buffer[i++] = 1;
                        buffer[i++] = 0; // class IN
                        buffer[i++] = 1;
                        Put32(buffer, &i, 0xe3000000); // time to live = 3 minutes 47 seconds
                        Put16(buffer, &i, 0x400); // address length = 4
                        Put32(buffer, &i, u32MyAddr); // our IP address (web server)
                        sendto(listen_sock, buffer, i, 0, (struct sockaddr *)&addrfrom, addrLen);
                    }
                    else // forward the request to a real DNS server
                    {
if (!bRAW)
{
			rc = sendto(listen_sock, buffer, iOrigLen, 0, (struct sockaddr *)&fwaddr, sizeof(struct sockaddr));
			if (rc < 0) printf("Error sending request to real DNS server = %d\n", errno);
}
#ifndef __MACH__
else // using RAW socket
{
			// Our own headers' structures
			char localbuf[512], pseudogram[512];
			int offset;
			struct iphdr *iph;
			struct udphdr *udph;
			struct pseudo_header psh;

			memset(localbuf, 0, 512);
			offset = 0;
			iph = (struct iphdr *)&localbuf[offset];
			offset += sizeof(struct iphdr);
			udph = (struct udphdr *)&localbuf[offset];
			offset += sizeof(struct udphdr);
			memcpy(&localbuf[offset], buffer, iOrigLen); // original msg

			// Fabricate the IP header or we can use the
			// standard header structures but assign our own values.
			iph->ihl = 5;
			iph->version = 4;
			iph->tos = 0; // no delay
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + iOrigLen;
			iph->id = htons(54321);
			iph->ttl = 255; // hops
			iph->protocol = IPPROTO_UDP; // UDP
			// Source IP address, can use spoofed address here!!!
			iph->saddr = addrfrom.sin_addr.s_addr;
			// The destination IP address
			iph->daddr = fwaddr.sin_addr.s_addr;
			iph->check = csum ((unsigned short *) iph, iph->tot_len);
			// Fabricate the UDP header. Source port number, redundant
			udph->source = addrfrom.sin_port;
			// Destination port number
			udph->dest = htons(53);
			udph->len = htons(iOrigLen + sizeof(struct udphdr));
			// now the pseudo header
			psh.src_addr = addrfrom.sin_addr.s_addr;
			psh.dst_addr = fwaddr.sin_addr.s_addr;
			psh.placeholder = 0;
			psh.protocol = IPPROTO_UDP;
			psh.udp_length = htons(sizeof(struct udphdr) + iOrigLen);

			memcpy(pseudogram, &psh, sizeof(psh));
			memcpy(&pseudogram[sizeof(psh)], udph, sizeof(struct udphdr) + iOrigLen);
			udph->check = csum((unsigned short*)pseudogram, sizeof(psh)+sizeof(struct udphdr) + iOrigLen);
                        rc = sendto(forward_sock, localbuf, iph->tot_len, 0, (struct sockaddr *)&fwaddr, sizeof(fwaddr));
			if (rc < 0)
				printf("raw sendto returned %d and errno=%d\n", rc, errno);
} // RAW socket logic
#endif // __MACH__
                    }
                } // DNS query
		else // DNS response (pass it back to original requester
		{
		struct sockaddr_in destaddr;
			destaddr.sin_family = AF_INET;
			destaddr.sin_port = pPortIDs[u16Trans];
			destaddr.sin_addr.s_addr = pTransIDs[u16Trans];
			rc = sendto(listen_sock, buffer, iOrigLen, 0, (struct sockaddr *)&destaddr, sizeof(struct sockaddr)); 
			if (rc < 0)
				printf("proxy: sendto returned error %d\n", errno);
			//else
			//	printf("sending response back to %08x, rc=%d\n", pTransIDs[u16Trans], rc);
			//DumpData(buffer, iOrigLen);
		}
            }
            else
            {
                printf("timeout or socket error, rc=%d, errno=%d\n", rc, errno);
            }
            
        } // while running
    }
	return NULL;
} /* DNS_Thread() */
//
// Convert string to lower case
//
int FixString(unsigned char *string)
{
    int iLen = 1; // terminator
   while (*string)
   {
      if (string[0] >= 'A' && string[0] <= 'Z')
         string[0] += 32;
       iLen++;
      string++;
   }
    return iLen;
} /* FixString() */

//
// Parse a list of blocked domains
// Count the lines and find the total storage needed for the text
//
int ParseText(unsigned char *pText, int iLen, int *iTotalSize)
{
    int i, j, iLines, iStart, iDot;
    uint32_t iOffset = 0; // offset into string memory
    int iSize = 0;
    
    i = iLines = 0;
    while (i < iLen) // parse the input file and extract the domain names
    {
        iStart = i;
        while (pText[i] > ' ' && i < iLen) // find end of line
        {
            i++;
        }
        if (iStart != i) // a non-empty string was found
        {
            pText[i] = 0; // zero terminate it
            // work backwards to get root domain name
            j = i-1;
            iDot = 0;
            while (j > iStart && iDot < 2)
            {
                if (pText[j] == '.') iDot++;
                j--;
            }
            if (iDot == 2) iStart = j+2;
            if (iTotalSize) // we're gathering stats
            {
                iSize += strlen((const char *)&pText[iStart]) + 1; // bytes needed to hold this string
                iLines++;
            }
            else
            {
                j = FixString(&pText[iStart]); // make it lower case
                strcpy((char *)&pListData[iOffset], (char *)&pText[iStart]);
                pOffsets[iListSize++] = iOffset; // store the starting offset of this line
                iOffset += j; // advance to next available space
            //printf("root domain: %s\n", &pText[iStart]);
            }
        }
        // skip past any other LF/CR/SPACES
        while (i < iLen && pText[i] <= ' ')
        {
            i++;
        }
    }
    
    if (iTotalSize) *iTotalSize = iSize; // just gathering stats
    return iLines;
} /* ParseText() */

//
// QSORT string comparison function
//
int name_compare(const void *ina, const void *inb)
{
    uint32_t *pa = (uint32_t *)ina; // pointer to list offsets
    uint32_t *pb = (uint32_t *)inb;
    unsigned char *a, *b;
    
    a = &pListData[*pa];
    b = &pListData[*pb];
    
    while (*a && *b) {
        if (*a != *b) {
            break;
        }
        ++a;
        ++b;
    }
    return (int)(*a - *b);
} /* name_compare() */

//
// See if the domain name is in the blocked list
// return TRUE if found
//
int FindMatch(unsigned char *s)
{
    int i, iTLC, iCount, iStart;
    
    iTLC = (ucCharTranslate[s[0]] << 12); // form 18-bit index from first 3 characters
    iTLC |= (ucCharTranslate[s[1]] << 6);
    iTLC |= (ucCharTranslate[s[2]]);
    if ((iCount = pListLens[iTLC]) == 0) // not found
        return 0;
    // Search within the found list
    FixString(s);
    iStart = pListHeads[iTLC];
    for (i=iStart; i<iStart+iCount; i++) // DEBUG - change to binary search
    {
        if (strcmp((char *)s, (char *)&pListData[pOffsets[i]]) == 0) // found it
            return 1;
    }
    return 0;
} /* FindMatch() */

//
// Go through the aggregate (final) block list and remove repeated domains
//
void RemoveRepeats(void)
{
    int i, j;
    for (i=1; i<iListSize; i++)
    {
        if (strcmp((char *)&pListData[pOffsets[i]], (char *)&pListData[pOffsets[i-1]]) == 0)
        {
            for (j=i; j<iListSize-1; j++) // remove this line
            {
                pOffsets[j] = pOffsets[j+1];
            }
            iListSize--;
        }
    } // for each line
} /* RemoveRepeats() */

//
// Load an asset (e.g. image file) to deliver to blocked sites
// as a fake response
//
// returns a pointer to the buffer or NULL if it fails to open
//
uint8_t * LoadAsset(char *szName, int *pLen)
{
void *pf;
uint8_t *pAsset = NULL;

	pf = PILIOOpen(szName);
	if (pf != (void *)-1)
	{
		*pLen = PILIOSize(pf);
		pAsset = (uint8_t *)PILIOAlloc(*pLen);
		if (!pAsset)
		{
			PILIOClose(pf);
			return NULL;
		}
		PILIORead(pf, pAsset, *pLen);
		PILIOClose(pf);
	}
	return pAsset;
} /* LoadAsset() */

//
// Add a list of blocked domain names to the aggregate list
// returns 1 for success, 0 for failure
//
int AddList(char *szName)
{
void *pf;
int iLen, i, j;
int iLines, iTotalSize;
int iTLC, iTLC_Old;
unsigned char *pText;

	pf = PILIOOpen(szName);
	if (pf != (void *)-1)
	{
		iLen = PILIOSize(pf);
        printf("%s: %d Bytes\n", szName, iLen);
		pText = (unsigned char *)PILIOAlloc(iLen);
		if (!pText)
		{
			PILIOClose(pf);
			return 0;
		}
		PILIORead(pf, pText, iLen);
		PILIOClose(pf);
		iLines = ParseText(pText, iLen, &iTotalSize); // count the number of lines
        if (pOffsets) // add to existing list
        {
        }
        else // starting a new list
        {
            pOffsets = PILIOAlloc(iLines * sizeof(uint32_t)); // memory for the line offsets
            pListData = PILIOAlloc(iTotalSize); // memory for the text
            iListSize = 0; // starting fresh
        }
        ParseText(pText, iLen, NULL); // extract the strings and add them to the indexed list
        printf("Lines: %d, total size: %d\n", iLines, iTotalSize);
        PILIOFree(pText);
        // Sort the new list alphabetically
        qsort(pOffsets, iListSize, 4, name_compare); // sort the list
        RemoveRepeats();
        // Create the lists of 3-letter prefixes for faster searches
        iTLC_Old = -1; // last code found
        j = 1; // number of matches
        for (i=0; i<iListSize; i++)
        {
            unsigned char *s = &pListData[pOffsets[i]];
            iTLC = (ucCharTranslate[s[0]] << 12); // form 18-bit index from first 3 characters
            iTLC |= (ucCharTranslate[s[1]] << 6);
            iTLC |= (ucCharTranslate[s[2]]);
            if (iTLC != iTLC_Old) // starting a new list
            {
                pListHeads[iTLC] = i;
                pListLens[iTLC] = 1; // init to 1 entry to start
                if (iTLC_Old != -1)
                    pListLens[iTLC_Old] = (unsigned char)j;
                iTLC_Old = iTLC;
                j = 1; // reset match count
            }
            else // still matches, increment count
            {
                j++;
            }
        }
        if (j != 1) // need to store the last matches
        {
            pListHeads[iTLC_Old] = j;
        }
	}
	else
	{
		printf("Error opening file %s\n", szName);
		return 0;
	}
	return 1;
} /* AddList() */

int AddMsg(char *p, int iLen, char *szString)
{
int i;

	i = strlen(szString);
	memcpy(&p[iLen], szString, i);
	iLen += i;
	p[iLen++] = 0xd; // add CR/LF to end of each line
	p[iLen++] = 0xa;
	return iLen;
} /* AddMsg() */

//
// Parse the HTTP request type
//
int ParseHTTP(char *ucMsg, int iLen)
{
int iType = -1;
char szTemp[MAX_STRING];
int i, j;

	if (memcmp(ucMsg, "GET", 3) == 0)
	{
		i = 4;
		j = 0;
		while (i < iLen && ucMsg[i] != ' ' && j < MAX_STRING) // capture URL
		{
			szTemp[j++] = ucMsg[i++];
		}
		szTemp[j] = '\0';
		if (j > 4)
		{
			FixString((unsigned char *)szTemp); // convert to lower case
			if (strcmp(szTemp, "/report.html") == 0)
				iType = RESPONSE_REPORT;
			else if (strcmp(szTemp, "/") == 0) // empty request for index.htm
				iType = RESPONSE_INDEX;
			else if (memcmp(&szTemp[j-4], ".gif",4) == 0)
				iType = RESPONSE_GIF;
			else if (memcmp(&szTemp[j-4], ".jpg",4) == 0)
				iType = RESPONSE_JPG;
			else if (memcmp(&szTemp[j-4], ".png",4) == 0)
				iType = RESPONSE_PNG;
			else if (memcmp(&szTemp[j-4], ".htm",4) == 0)
				iType = RESPONSE_HTML;
            else if (memcmp(&szTemp[j-3], ".js",3) == 0)
                iType = RESPONSE_JSCRIPT;
			else if (memcmp(&szTemp[j-5], ".html",5) == 0)
				iType = RESPONSE_HTML;
		}
	}
	if (iType == -1) // didn't match, check the accepted response type
	{
		i = 4;
		while (i < iLen)
		{
			if (memcmp(&ucMsg[i], "Accept: image", 13) == 0)
			{
				iType = RESPONSE_JPG; // give it a JPEG
				break;
			}
			i++;
		}
		if (i == iLen) // couldn't find an image request, assume javascript
			iType = RESPONSE_JSCRIPT;
	}
    if (bVerbose)
        printf("HTTP Request: %s, type=%s\n", szTemp, szTypes[iType+1]);

	return iType;
} /* ParseHTTP() */

int PrepareHeader(char *pHeader, int iType, int iMsgLen)
{
int iLen = 0;
char szTemp[MAX_STRING];

	iLen = AddMsg(pHeader, iLen, "HTTP/1.0 200 OK");
//	iLen = AddMsg(pHeader, iLen, "Accept-Ranges: bytes");
	iLen = AddMsg(pHeader, iLen, "Connection: close");
	if (iType == RESPONSE_REPORT || iType == RESPONSE_HTML)
		iLen = AddMsg(pHeader, iLen, "Content-Type: text/html");
	else if (iType == RESPONSE_GIF)
		iLen = AddMsg(pHeader, iLen, "Content-Type: image/gif");
	else if (iType == RESPONSE_PNG)
		iLen = AddMsg(pHeader, iLen, "Content-Type: image/png");
	else if (iType == RESPONSE_JPG)
		iLen = AddMsg(pHeader, iLen, "Content-Type: image/jpeg");
    else if (iType == RESPONSE_JSCRIPT)
        iLen = AddMsg(pHeader, iLen, "Content-Type: application/javascript");
	sprintf(szTemp,"Content-Length: %d", iMsgLen);
	iLen = AddMsg(pHeader, iLen, szTemp);
	iLen = AddMsg(pHeader, iLen, ""); // blank line indicating end of header
	return iLen;
} /* PrepareHeader() */

//
// Prepare a status report on the server
//
int PrepareReport(char *pMsg)
{
char szTemp[MAX_STRING];

	strcpy(pMsg, "<html><head><h1>Usage Report</h1></head><br>\r\n");
	sprintf(szTemp, "Blacklist length: %d<br>\r\n", iListSize);
	strcat(pMsg, szTemp);
	sprintf(szTemp, "Total DNS Requests: %d<br>\r\n", iDNSRequests);
	strcat(pMsg, szTemp);
	sprintf(szTemp, "Total HTTP Requests: %d<br>\r\n", iHTTPRequests);
	strcat(pMsg, szTemp);
	sprintf(szTemp, "Total Blocked: %d<br>\r\n", iBlocked);
	strcat(pMsg, szTemp);
	sprintf(szTemp, "<img src=\"thisisatest.gif\" alt=\"GIF test\"><br>\n");
	strcat(pMsg, szTemp);
	sprintf(szTemp, "<img src=\"thisisatest.jpg\" alt=\"JPEG test\"><br>\n");
	strcat(pMsg, szTemp);
	sprintf(szTemp, "<img src=\"thisisatest.png\" alt=\"PNG test\"><br>\n");
	strcat(pMsg, szTemp);
	return strlen(pMsg);
} /* PrepareReport() */

#ifdef SHOW_STATS_OLED
void *OLED_Thread(void *unused)
{
char szTemp[64];

	oledFill(0);
	oledSetContrast(40); // slightly dim since it's on 24/7
	inet_ntop(AF_INET, &u32MyAddr, szTemp, INET_ADDRSTRLEN);
	oledWriteString(0,0,szTemp,0);
	oledWriteString(0,1,"----------------",0);

	while (bRunning)
	{
		sprintf(szTemp, "List: %d      ", iListSize);
		oledWriteString(0,2,szTemp,0);
		sprintf(szTemp, "DNS Reqs: %d     ", iDNSRequests);
		oledWriteString(0,3,szTemp, 0);
		sprintf(szTemp, "HTTP Reqs: %d     ", iHTTPRequests);
		oledWriteString(0,4,szTemp,0);
		sprintf(szTemp, "Blocked: %d     ", iBlocked);
		oledWriteString(0,5,szTemp,0);
		usleep(1000000);
	}
	oledShutdown();
	return NULL;
} /* OLED_Thread() */
#endif // SHOW_STATS_OLED

void * HTTP_Thread(void *unused)
{
int read_sock;
struct sockaddr_in addr_remote, addr_server;
int i;
socklen_t len;
char ucHeader[MAX_DNS], ucMsg[MAX_HTTP];
int iHeaderLen, iMsgLen;

	server_sock = socket(AF_INET,SOCK_STREAM, 0);

	if (server_sock == -1)
	{
		printf("HTTP Server socket failed to create\n");
	}
       memset(&addr_server, 0, sizeof(addr_server));
       addr_server.sin_family = AF_INET;
       addr_server.sin_port = htons(80); // use HTTP port
       addr_server.sin_addr.s_addr = INADDR_ANY; // accept from any on that port
       i = bind(server_sock, (struct sockaddr *)&addr_server, sizeof(addr_server));
	if (i == -1)
	{
		printf("Binding socket to port 80 failed\n");
	}
	i = listen(server_sock, 0); // listen for incoming connections
	
        while (bRunning)
        {
		len = sizeof(struct sockaddr);
		read_sock = accept(server_sock, (struct sockaddr *)&addr_remote, &len);
		if (read_sock != -1)
		{
		int count, iReady, iType;
		char *pMsg;
			iHTTPRequests++;
//			printf("connection request, read addr = %08x\n", addr_remote.sin_addr.s_addr);
			iReady = iMsgLen = 0;
			while (!iReady) // read the whole message
			{
				ioctl(read_sock, FIONREAD, &count); // see how many bytes we can read
//				printf("ioctl says %d bytes waiting\n", count);
                // Don't let our buffer overflow; HTTP request shouldn't be this long anyway
                if (iMsgLen + count > MAX_HTTP)
                {
                    count = MAX_HTTP - iMsgLen;
                }
				count = recv(read_sock, &ucMsg[iMsgLen], count, 0);
				iMsgLen += count;
				if (count == 0) // no more data waiting
				{
					usleep(5000); // allow time for more data to arrive
					if (iMsgLen == 0) continue;
				}
				iReady = 1; // DEBUG 
			}
			//DumpData((unsigned char *)ucMsg, iMsgLen);
			iType = ParseHTTP(ucMsg, iMsgLen); // see what type of request we got
//			printf("HTTP request to server, type=%s\n", szTypes[iType+1]);
			if (iType == -1)
			{
				DumpData((unsigned char *)ucMsg, iMsgLen);
			}
			iHeaderLen = 0;
			pMsg = ucMsg;
			switch (iType)
			{
				case RESPONSE_REPORT:
					iMsgLen = PrepareReport(ucMsg);
					iHeaderLen = PrepareHeader(ucHeader, iType, iMsgLen);
					pMsg = ucMsg;
					break;
				case RESPONSE_HTML: // simple response
					strcpy(ucMsg, "<html><head><h1>site blocked!</h1></head></html>\r\n");
					iMsgLen = strlen(ucMsg);
					iHeaderLen = PrepareHeader(ucHeader, iType, iMsgLen);
					pMsg = ucMsg;
					break;
				case RESPONSE_JPG: // give it a simple image
					iMsgLen = iJPEGSize;
					iHeaderLen = PrepareHeader(ucHeader, iType, iMsgLen);
					pMsg = (char *)pJPEG;
					break;
				case -1:
				case RESPONSE_PNG: // give it a simple image
					iMsgLen = iPNGSize;
					iHeaderLen = PrepareHeader(ucHeader, iType, iMsgLen);
					pMsg = (char *)pPNG;
					break;
                case RESPONSE_JSCRIPT:
                    iMsgLen = iJavaScriptSize;
                    pMsg = (char *)pJavaScript;
                    iHeaderLen = PrepareHeader(ucHeader, iType, iMsgLen);
                    break;
				case RESPONSE_GIF: // give it a simple image
					iMsgLen = iGIFSize;
					iHeaderLen = PrepareHeader(ucHeader, iType, iMsgLen);
					pMsg = (char *)pGIF;
					break;
			}
			send(read_sock, ucHeader, iHeaderLen, 0);
			send(read_sock, pMsg, iMsgLen, 0);
			close(read_sock);
		}
		else
		{
			printf("Socket timeout or bad connection request\n");
		}
	}
	return NULL;
} /* HTTP_Thread() */

static int ParseOpts(int argc, char * const argv[])
{
    char szTemp[32];
    int i = 1;
    
    // Set default options
    bVerbose = 0;
    bStats = 0;
    bRAW = 0;
    strcpy(szTemp, "8.8.8.8");
    
    while (i < argc)
    {
        /* if it isn't a cmdline option, we're done */
        if (0 != strncmp("--", argv[i], 2))
            break;
        /* test for each specific flag */
        if (0 == strcmp("--verbose", argv[i])) {
            bVerbose = 1;
            i++;
        } else if (0 == strcmp("--stats", argv[i])) {
            bStats = 1;
            i++;
#ifndef __MACH__
        } else if (0 == strcmp("--raw", argv[i])) {
            bRAW = 1;
            i++;
#endif // __MACH__
        } else if (0 == strcmp("--dns", argv[i])) {
            strcpy(szTemp, argv[i+1]);
            i += 2;
        }  else {
            fprintf(stderr, "Unknown parameter '%s'\n", argv[i]);
            exit(1);
        }
    }
    // convert DNS server IP address from ASCII to int
    inet_pton(AF_INET, szTemp, &u32DNS);
    
    return i;
    
} /* ParseOpts() */

int main( int argc, char *argv[])
{
int i, argc_off, iTime;
pthread_t tinfo;
char cCommand, interface[16], address[16];
char *p, szCWD[MAX_STRING], szAsset[512]; // current working dir

	if (argc < 2)
	{
	ShowHelp();
	return 0;
	}
    argc_off = ParseOpts(argc, argv);
    
	bRunning = 1;
	GetIPAddress(interface, address);
#ifdef SHOW_STATS_OLED
	i = oledInit(0, 0x3c);
	if (i == 0)
		pthread_create(&tinfo, NULL, OLED_Thread, NULL);
#endif // SHOW_STATS_OLED

// Get our own IP address
	printf("intf=%s, addr=%s\n", interface, address);
	u32MyAddr = inet_addr(address);
	printf("My IP address = %08x\n", u32MyAddr);

// Load local image assets for blackhole http server
	p = getcwd(szCWD, MAX_STRING);
	if (p)
	{
		strcpy(szAsset, p);
		strcat(szAsset, "/blocked.gif");
		pGIF = LoadAsset(szAsset, &iGIFSize);
		strcpy(szAsset, p);
		strcat(szAsset, "/blocked.png");
		pPNG = LoadAsset(szAsset, &iPNGSize);
		strcpy(szAsset, p);
		strcat(szAsset, "/blocked.jpg");
		pJPEG = LoadAsset(szAsset, &iJPEGSize);
        iJavaScriptSize = strlen(pJavaScript);
		printf("Assets loaded; gif=%d bytes, png=%d bytes, jpg=%d bytes\n", iGIFSize, iPNGSize, iJPEGSize);
	}
// Prepare to add lists
	iListSize = 0;
	pListHeads = PILIOAlloc(THREE_SIZE * sizeof(uint32_t));
	pListLens = PILIOAlloc(THREE_SIZE * sizeof(uint8_t));

// DEBUG - temporary transaction ID list for proxy until we get packet forwarding to work
	pTransIDs = PILIOAlloc(65536 * sizeof(uint32_t));
	pPortIDs = PILIOAlloc(65536 * sizeof(uint16_t));

// Add each list to our aggregate list
    iTime = MilliTime();
	for (i=argc_off; i<argc; i++)
	{
		AddList(argv[i]);
	}
    if (iListSize == 0) // no lists provided
    {
        printf("Empty block list, quitting!\n");
        goto quit;
    }
    iTime = MilliTime() - iTime;
    // print the list
   // for (i=0; i<iListSize; i++)
 //   {
 //       printf("domain: %s\n", (char *)&pListData[pOffsets[i]]);
 //   }
    printf("%d milliseconds to read+prepare block list(s)\n", iTime);
	printf("Total list size: %d unique entries\n", iListSize);
    pthread_create(&tinfo, NULL, HTTP_Thread, NULL);
    pthread_create(&tinfo, NULL, DNS_Thread, NULL);
    printf("DNS and Web server running...\n");
    printf("Enter the following commands:\n");
    printf("q - quit\n");
    printf("r - reload lists\n");
    printf("s - display statistics\n");
    cCommand = 0;
    while (cCommand != 'q')
    {
	cCommand = getchar();
	switch (cCommand)
	{
		case 'r':
			printf("reloading lists...\n");
			break;
		case 's':
			printf("Blacklist length: %d\n", iListSize);
			printf("Total DNS Requests: %d\n", iDNSRequests);
			printf("Total HTTP Requests: %d\n", iHTTPRequests);
			printf("Blocked: %d (%02.1f%%)\n", iBlocked, (100.0*(float)iBlocked)/(float)iDNSRequests);
			break;
		case 'q':
			printf("Shutting down...\n");
			goto quit;
	}
    }
quit:
        bRunning = 0;
        close(server_sock);
        close(listen_sock);
        usleep(100000); // allow threads to exit

	PILIOFree(pListHeads);
	PILIOFree(pListLens);
	PILIOFree(pTransIDs); // DEBUG
	PILIOFree(pPortIDs);
return 0;
}
