/*
 * This file is part of 7350natter.
 *
 * (C) 200x-2018 by Sebastian Krahmer,
 *               sebastian [dot] krahmer [at] gmail [dot] com
 *
 * 7350natter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * 7350natter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with 7350natter. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <list>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <iostream>


using namespace std;

namespace natter {


// Just forgot where this was taken from. Some public domain in-cksum
unsigned short
in_cksum (unsigned short *ptr, int nbytes, bool may_pad)
{

  register long sum;		/* assumes long == 32 bits */
  u_short oddbyte;
  register u_short answer;	/* assumes u_short == 16 bits */


  /* For psuedo-headers: odd len's require
   * padding. We assume that UDP,TCP always
   * gives enough room for computation */
  if (nbytes % 2 && may_pad)
	++nbytes;
  /*
   * Our algorithm is simple, using a 32-bit accumulator (sum),
   * we add sequential 16-bit words to it, and at the end, fold back
   * all the carry bits from the top 16 bits into the lower 16 bits.
   */

  sum = 0;
  while (nbytes > 1)
    {
      sum += *ptr++;
      nbytes -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nbytes == 1)
    {
      oddbyte = 0;		/* make sure top half is zero */
      *((unsigned char *) & oddbyte) = *(unsigned char *) ptr;	/* one byte only */
      sum += oddbyte;
    }

  /*
   * Add back carry outs from top 16 bits to low 16 bits.
   */

  sum = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* ones-complement, then truncate to 16 bits */
  return (answer);
}



class ICMPTest {
private:
	int sfd;
	string error;
	int ai_family;
	struct sockaddr_in to;
	struct sockaddr_in6 to6;
	list<string> routers;

public:
	ICMPTest(int ai_family);

	~ICMPTest();

	// send ICMP packet with certain TTL
	int sendttl(int);

	// Return name of host complaining about
	// time exceeded or "done" if finished.
	// Should call sendttl() before.
	string rcverr();

	int peer(const string &);

	const char *why() { return error.c_str(); };

	int pending_error() { return error.size() > 1; };

};


ICMPTest::ICMPTest(int p_ai_family)
{
	error = "";
	int proto = 0;

	memset(&to, 0, sizeof(to));
	memset(&to6, 0, sizeof(to6));

	if (p_ai_family == AF_INET6)
		proto = IPPROTO_ICMPV6;
	else
		proto = IPPROTO_ICMP;

	if ((sfd = socket(p_ai_family, SOCK_RAW, proto)) < 0) {
		error = "ICMPTest::ICMPTest::socket:";
		error += strerror(errno);
	}
	ai_family = p_ai_family;
}


ICMPTest::~ICMPTest()
{
	close(sfd);
}


int ICMPTest::peer(const string &peername)
{
	struct addrinfo *resp, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai_family;

	if (getaddrinfo(peername.c_str(), NULL, &hints, &resp) != 0) {
		error = "ICMPTest::peer::getaddrinfo:";
		error += strerror(errno);
		return -1;
	}

	if (ai_family == AF_INET6) {
		to6.sin6_addr = ((struct sockaddr_in6*)resp->ai_addr)->sin6_addr;
		to6.sin6_family = AF_INET6;
		to6.sin6_port = htons(IPPROTO_ICMPV6);
	} else {
		to.sin_addr = ((struct sockaddr_in*)resp->ai_addr)->sin_addr;
		to.sin_family = AF_INET;
		to.sin_port = htons(IPPROTO_ICMP);
	}

	freeaddrinfo(resp);

	return 0;
}


int ICMPTest::sendttl(int ttl)
{
	struct icmphdr {
		u_int8_t type;
		u_int8_t code;
		u_short  sum, id, seq;

		char pl[1];
	};
	struct sockaddr *pto;
	socklen_t tolen;
	// ECHO REQUEST
	icmphdr ih = {8, 0, 0, 7350, 1};
	socklen_t olen = sizeof(ttl);

	ih.pl[0] = 'X';

	// If ICMPv6 then we need different ICMP-type
	// and no checksum
	if (ai_family == AF_INET6)
		ih.type = 128; // ICMPv6 ECHO REQUEST
	else
		ih.sum = in_cksum((u_short*)&ih, sizeof(ih), 0);

	if (ai_family == AF_INET6) {
		pto = (struct sockaddr*)&to6;
		tolen = sizeof(to6);
	} else {
		pto = (struct sockaddr*)&to;
		tolen = sizeof(to);
	}

	int level = IPPROTO_IP, optname = IP_TTL;
	if (ai_family == AF_INET6) {
		level = IPPROTO_IPV6;
		optname = IPV6_UNICAST_HOPS;
	}

	// set TTL respective HOP-limit in IP hdr
	if (setsockopt(sfd, level, optname, &ttl, olen) < 0) {
		error = "ICMPTest::sendttl::setsockopt:";
		error += strerror(errno);
		return -1;
	}

	if (sendto(sfd, &ih, sizeof(ih), 0, pto, tolen) < 0) {
		error = "ICMPTest::sendttl::sendto:";
		error += strerror(errno);
		return -1;
	}
	return 0;
}


string ICMPTest::rcverr()
{
	char buf[1024], *ptr;
	struct sockaddr *fromp;
	struct sockaddr_in from;
	struct sockaddr_in6 from6;
	socklen_t flen;
	int r;
	string s;
	fd_set rset;

	if (ai_family == AF_INET) {
		fromp = (sockaddr*)&from;
		flen = sizeof(from);
	} else {
		fromp = (sockaddr*)&from6;
		flen = sizeof(from6);
	}

	FD_ZERO(&rset);
	FD_SET(sfd, &rset);
	struct timeval tv = {3, 0};
	if (select(sfd+1, &rset, NULL, NULL, &tv) < 0) {
		error = "ICMPTest::rcverr::select:";
		error += strerror(errno);
		return "ERROR";
	}
	if (!FD_ISSET(sfd, &rset)) {
		error = "No reply within 3 seconds.";
		return "TIMEOUT";
	}

	ptr = buf;
	r = recvfrom(sfd, buf, sizeof(buf), 0, fromp, &flen);
	if (r < 0) {
		error = "ICMPTest::rcverr::recvfrom:";
		error += strerror(errno);
		return "ERROR";
	}
	if (r < 20 + 8) {
		error = "Received invalid packet. Aborting.";
		return "ERROR";
	}

	if (ai_family == AF_INET) {
		ptr += (ptr[0] & 0xf)<<2;	// jump over IP-hdr
		if (ptr[0] == 11) {		// Time exceeded
			inet_ntop(ai_family, (char*)&from.sin_addr, buf, sizeof(buf));
			s = buf;
			routers.push_back(s);
		} else
			s = "done";
	} //TODO: IPv6
	return s;
}


class TCPTest {
private:
	int sfd;
	string error;
	int ai_family;
	struct sockaddr_in to;
	struct sockaddr_in6 to6;
	list<string> routers;

	ICMPTest *i;

public:

	TCPTest(int family);

	~TCPTest();

	// send TCP packet with certain TTL
	int connectttl(int);

	int peer(const string &, uint16_t lport, uint16_t rport);

	string rcverr();

	const char *why() { return error.c_str(); };

	int pending_error() { return error.size() > 1; };


};


TCPTest::TCPTest(int p_ai_family)
{
	error = "";

	memset(&to, 0, sizeof(to));
	memset(&to6, 0, sizeof(to6));

	ai_family = p_ai_family;

	i = new (nothrow) ICMPTest(ai_family);
}


TCPTest::~TCPTest()
{
	delete i;
}


int TCPTest::peer(const string &peername, uint16_t lport, uint16_t rport)
{

	struct addrinfo *resp, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai_family;

	if (getaddrinfo(peername.c_str(), NULL, &hints, &resp) != 0) {
		error = "ICMPTest::peer:getaddrinfo:";
		error += strerror(errno);
		return -1;
	}

	if (ai_family == AF_INET6) {
		to6.sin6_addr = ((struct sockaddr_in6*)resp->ai_addr)->sin6_addr;
		to6.sin6_family = AF_INET6;
		to6.sin6_port = htons(rport);
	} else {
		to.sin_addr = ((struct sockaddr_in*)resp->ai_addr)->sin_addr;
		to.sin_family = AF_INET;
		to.sin_port = htons(rport);
	}

	freeaddrinfo(resp);

	return 0;
}

// returns 0 if TTL less than needed,
// 1 if correct TTL is reached and -1 on error
int TCPTest::connectttl(int ttl)
{
	struct sockaddr *pto;
	socklen_t tolen;

	if ((sfd = socket(ai_family, SOCK_STREAM, 0)) < 0) {
		error = "TCPTest::sendttl::socket:";
		error += strerror(errno);
		return -1;
	}

	if (ai_family == AF_INET6) {
		pto = (struct sockaddr*)&to6;
		tolen = sizeof(to6);

	} else {
		pto = (struct sockaddr*)&to;
		tolen = sizeof(to);

	}

	// TODO: bind to local port
	int level = IPPROTO_IP, optname = IP_TTL;
	if (ai_family == AF_INET6) {
		level = IPPROTO_IPV6;
		optname = IPV6_UNICAST_HOPS;
	}

	int olen = sizeof(ttl);

	// set TTL respective HOP-limit in IP hdr
	if (setsockopt(sfd, level, optname, &ttl, olen) < 0) {
		error = "TCPTest::sendttl::setsockopt";
		error += strerror(errno);
		return -1;
	}


	if (connect(sfd, pto, tolen) < 0) {
		if (errno == ECONNREFUSED) {
			cout<<"TTL "<<(int)ttl<<" -> connREFUSED\n";
			return 1;
		}
	} else {
		cout<<"TTL "<<(int)ttl<<" -> connected\n";
		return 1;
	}

	close(sfd);
	return 0;
}


string TCPTest::rcverr()
{
	string s = i->rcverr();
	error = i->why();
	return s;
}


}

using namespace natter;

int main(int argc, char **argv)
{

	if (argc < 2) {
		cerr<<"Usage: 7350natter <dst> [dstport]\n";
		exit(1);
	}

	uint16_t rport = 443;
	if (argc == 3)
		rport = strtoul(argv[2], NULL, 10);

	ICMPTest *it = new (nothrow) ICMPTest(AF_INET);

	if (it->pending_error()) {
		cerr<<it->why()<<endl;
		exit(1);
	}

	if (it->peer(argv[1]) < 0) {
		cerr<<it->why()<<endl;
		exit(1);
	}

	string s;
	int ttl;
	for (ttl = 1;; ttl++) {
		if (it->sendttl(ttl) < 0) {
			cerr<<it->why()<<endl;
			exit(1);
		}
		s = it->rcverr();
		if (s == "ERROR") {
			cerr<<"ERROR: "<<it->why()<<endl;
			exit(1);
		} else if (s == "TIMEOUT") {
			cerr<<"O"; --ttl;
			continue;
		}
		cerr<<"o";
		if (s == "done")
			break;
	}
	delete it;
	cerr<<endl<<"ICMP TTL: "<<ttl<<endl;

	TCPTest *tt = new (nothrow) TCPTest(AF_INET);
	tt->peer(argv[1], 0, rport);

	int r;
	for (ttl = 1;; ttl++) {
		r = tt->connectttl(ttl);
		if (r < 0) {
			cerr<<tt->why();
			exit(1);
		} else if (r == 1) {
			cout<<"done\n"; break;
		}

		s = tt->rcverr();
		if (s == "ERROR") {
			cerr<<"ERROR: "<<tt->why()<<endl;
			exit(1);
		} else if (s == "TIMEOUT") {
			cout<<"T\n"; --ttl;
			continue;
		}
		cout<<s<<endl;
	}

	delete tt;
	return 0;
}


