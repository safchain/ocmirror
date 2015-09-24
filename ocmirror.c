/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * Author: Sylvain Afchain (safchain@redhat.com)
 */

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>

#define UDP_PKT_SIZE  64536

enum
{
  TEXT_OUTPUT = 1,
  JSON_OUTPUT
};

enum
{
  IPV4 = 4,
  IPV6 = 6
};

enum pcap_type
{
  PCAP_CAPTURE_HOST = 1,
  PCAP_FLAGS = 2,
  PCAP_SOURCE_VN = 3,
  PCAP_DEST_VN = 4,
  PCAP_TLV_END = 255
};

enum direction
{
  EGRESS,
  INGRESS
};

enum action
{
  ALERT = 1,
  DROP,
  DENY,
  LOG,
  PASS,
  REJECT,
  MIRROR,
  VRF_TRANSLATE,
  TRAP = 28,
  IMPLICIT_DENY,
  RESERVED,
  UNKNOWN,
};

struct pcap_metadata
{
  char ip_version;

  union
  {
    struct sockaddr_in addr_v4;
    struct sockaddr_in6 addr_v6;
  } host;

  char direction;
  unsigned int actions;

  char src_vn[256];
  char dst_vn[256];
};

char *
decode_metadata (char *pkt, unsigned int size, struct pcap_metadata *data)
{
  unsigned char type, length;
  char *ptr = pkt;

  bzero (data, sizeof (*data));
  for (;;) {
    if (size - (ptr - pkt) < 2) {
      return NULL;
    }
    type = *ptr++;
    length = *ptr++;

    if (size - (ptr - pkt) < length) {
      return NULL;
    }
    size -= length;

    if (type == PCAP_CAPTURE_HOST) {
      if (length == 4) {
        memcpy (&(data->host.addr_v4), ptr, length);
        data->ip_version = IPV4;
      }
      else if (length == 6) {
        memcpy (&(data->host.addr_v6), ptr, length);
        data->ip_version = IPV6;
      }
    }
    else if (type == PCAP_FLAGS) {
      data->actions = (ptr[0] << 24) +
        (ptr[1] << 16) + (ptr[2] << 8) + (ptr[3] & 0xff);
      if (data->actions & 0x40000000) {
        data->direction = INGRESS;
        data->actions &= ~0x40000000;
      }
      else {
        data->direction = EGRESS;
      }
    }
    else if (type == PCAP_SOURCE_VN) {
      memcpy (&(data->src_vn), ptr, length);
    }
    else if (type == PCAP_DEST_VN) {
      memcpy (&(data->dst_vn), ptr, length);
    }
    else if (type == PCAP_TLV_END) {
      ptr += length;
      break;
    }
    ptr += length;
  }

  return ptr;
}

int
open_forward_socket (const char *ifname, struct sockaddr_ll *laddr)
{
  struct ifreq if_idx;
  int sock;

  if ((sock = socket (AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
    return -1;
  }

  bzero (&if_idx, sizeof (if_idx));
  strncpy (if_idx.ifr_name, ifname, strlen (ifname));
  if (ioctl (sock, SIOCGIFINDEX, &if_idx) < 0) {
    return -1;
  }

  memset (laddr, 0, sizeof (struct sockaddr_ll));
  laddr->sll_ifindex = if_idx.ifr_ifindex;
  laddr->sll_halen = ETH_ALEN;

  return sock;
}

int
open_udp_socket (unsigned short port)
{
  struct sockaddr_in sin;
  int sock, size;

  if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    return -1;
  }

  size = 1;
  if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &size, sizeof (int)) == -1) {
    return -1;
  }

  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);

  if ((sin.sin_addr.s_addr = inet_addr ("0.0.0.0")) == INADDR_NONE) {
    return -1;
  }

  if (bind (sock, (struct sockaddr *) &sin, sizeof (struct sockaddr_in)) ==
      -1) {
    return -1;
  }

  return sock;
}

const char *
get_ether_type (unsigned short type)
{
  switch (type) {
  case ETHERTYPE_IP:
    return "IPv4";
  case ETHERTYPE_IPV6:
    return "IPv6";
  case ETHERTYPE_ARP:
    return "ARP";
  }

  return "Unknown";
}

const char *
get_protocol (unsigned char protocol)
{
  switch (protocol) {
  case 1:
    return "ICMP";
  case 6:
    return "TCP";
  case 17:
    return "UDP";
  }

  return "OTHER";
}

void
print_pkt (const char *pkt, unsigned int len, int verbose)
{
  struct ether_header *ether;
  struct ip *ip_hdr;
  const unsigned char *src, *dst;
  unsigned short type;
  char ip_src[BUFSIZ], ip_dst[BUFSIZ];
  int af;

  ether = (struct ether_header *) pkt;

  src = ether->ether_shost;
  dst = ether->ether_dhost;
  type = ntohs (ether->ether_type);
  if (verbose == JSON_OUTPUT) {
    printf ("\"hw_src\": \"%02x:%02x:%02x:%02x:%02x:%02x\", "
            "\"hw_dst\": \"%02x:%02x:%02x:%02x:%02x:%02x\", "
            "\"ethertype\": \"%s (%#.4x)\", \"length\": %d, ",
            src[0] & 0xff, src[1] & 0xff, src[2] & 0xff,
            src[3] & 0xff, src[4] & 0xff, src[5] & 0xff,
            dst[0] & 0xff, dst[1] & 0xff, dst[2] & 0xff,
            dst[3] & 0xff, dst[4] & 0xff, dst[5] & 0xff,
            get_ether_type (type), type, len);
  } else {
    printf ("\t"
            "%02x:%02x:%02x:%02x:%02x:%02x > "
            "%02x:%02x:%02x:%02x:%02x:%02x, "
            "ethertype %s (%#.4x), length: %d\n",
            src[0] & 0xff, src[1] & 0xff, src[2] & 0xff,
            src[3] & 0xff, src[4] & 0xff, src[5] & 0xff,
            dst[0] & 0xff, dst[1] & 0xff, dst[2] & 0xff,
            dst[3] & 0xff, dst[4] & 0xff, dst[5] & 0xff,
            get_ether_type (type), type, len);
  }

  if (type == ETHERTYPE_IP) {
    af = AF_INET;
  } else {
    af = AF_INET6;
  }

  ip_hdr = (struct ip *) (pkt + sizeof (struct ether_header));
  if (verbose == JSON_OUTPUT) {
    printf ("\"ip_src\": \"%s\", \"ip_dst\": \"%s\", "
            "\"length\": %d, \"protocol\": \"%s\"",
            inet_ntop (af, &(ip_hdr->ip_src), ip_src, sizeof (ip_src)),
            inet_ntop (af, &(ip_hdr->ip_dst), ip_dst, sizeof (ip_dst)),
            ntohs (ip_hdr->ip_len), get_protocol (ip_hdr->ip_p));
  } else {
    printf ("\t"
            "%s > %s length: %d, protocol: %s\n",
            inet_ntop (af, &(ip_hdr->ip_src), ip_src, sizeof (ip_src)),
            inet_ntop (af, &(ip_hdr->ip_dst), ip_dst, sizeof (ip_dst)),
            ntohs (ip_hdr->ip_len), get_protocol (ip_hdr->ip_p));
  }
}

const char *
get_metadata_next_actions (unsigned int *actions)
{
  if (*actions & (1 << ALERT)) {
    *actions &= ~(1 << ALERT);
    return "Alert";
  }
  if (*actions & (1 << DROP)) {
    *actions &= ~(1 << DROP);
    return "Drop";
  }
  if (*actions & (1 << DENY)) {
    *actions &= ~(1 << DENY);
    return "Deny";
  }
  if (*actions & (1 << LOG)) {
    *actions &= ~(1 << LOG);
    return "Log";
  }
  if (*actions & (1 << PASS)) {
    *actions &= ~(1 << PASS);
    return "Pass";
  }
  if (*actions & (1 << REJECT)) {
    *actions &= ~(1 << REJECT);
    return "Reject";
  }
  if (*actions & (1 << MIRROR)) {
    *actions &= ~(1 << MIRROR);
    return "Mirror";
  }
  if (*actions & (1 << VRF_TRANSLATE)) {
    *actions &= ~(1 << VRF_TRANSLATE);
    return "Vrf Translate";
  }
  if (*actions & (1 << TRAP)) {
    *actions &= ~(1 << TRAP);
    return "Trap";
  }
  if (*actions & (1 << IMPLICIT_DENY)) {
    *actions &= ~(1 << IMPLICIT_DENY);
    return "Implicit Deny";
  }
  if (*actions & (1 << UNKNOWN)) {
    *actions &= ~(1 << UNKNOWN);
    return "Unknown";
  }

  return "";
}

const char
*host_ip_str(const struct pcap_metadata *metadata, char *ip, int size) {
  if (metadata->ip_version == IPV4) {
    return inet_ntop (AF_INET, &(metadata->host.addr_v4), ip, size);
  }
  return inet_ntop (AF_INET6, &(metadata->host.addr_v6), ip, size);
}

void
print_metadata (const struct pcap_metadata *metadata, int verbose)
{
  const char *src, *dst, *action;
  unsigned int actions, n;
  char ip[BUFSIZ];

  if (metadata->direction == INGRESS) {
    src = metadata->src_vn;
    dst = metadata->dst_vn;
  }
  else {
    src = metadata->dst_vn;
    dst = metadata->src_vn;
  }

  actions = metadata->actions;
  if (verbose == JSON_OUTPUT) {
    printf("\"vn_src\": \"%s\", \"vn_dst\": \"%s\", "
           "\"host\": \"%s\", \"actions\": [", src, dst,
           host_ip_str(metadata, ip, sizeof (ip)));

    n = 0;
    while(actions) {
      action = get_metadata_next_actions(&actions);
      if (n) {
          printf(", \"%s\"", action);
      } else {
          printf("\"%s\"", action);
          n = 1;
      }
    }
    printf("], ");
  } else {
    printf ("%s > %s captured from: %s, action: ", src, dst,
            host_ip_str(metadata, ip, sizeof (ip)));

    n = 0;
    while(actions) {
      action = get_metadata_next_actions(&actions);
      if (n) {
          printf(", %s", action);
      } else {
          printf("%s", action);
          n = 1;
      }
    }
    printf ("\n");
  }
}

void
print_capture (const struct pcap_metadata *metadata, const char *pkt,
               unsigned int len, int verbose)
{
  struct timeval now;
  struct tm *loctime;
  char bufftime[BUFSIZ];

  gettimeofday (&now, NULL);
  loctime = gmtime (&(now.tv_sec));
  strftime (bufftime, BUFSIZ, "%H:%M:%S", loctime);

  if (verbose == JSON_OUTPUT) {
    printf ("{\"timestamp\": \"%s.%lu\", ", bufftime, now.tv_usec);
  } else {
    printf ("%s.%lu ", bufftime, now.tv_usec);
  }

  print_metadata (metadata, verbose);
  print_pkt (pkt, len, verbose);

  if (verbose == JSON_OUTPUT) {
    printf("}\n");
  }
}

void
forward (int usock, int fsock, const struct sockaddr_ll *fout, int verbose)
{
  struct pcap_metadata metadata;
  struct sockaddr_in uin;
  char pkt[UDP_PKT_SIZE], *ptr;
  unsigned int len;
  int r;

  for (;;) {
    len = sizeof (struct sockaddr_in);
    r = recvfrom (usock, pkt, UDP_PKT_SIZE, 0,
                  (struct sockaddr *) &uin, &len);
    if (r <= 0) {
      fprintf (stderr, "Error while reading the UDP socket: %s\n",
               strerror (errno));
      exit (-1);
    }

    ptr = decode_metadata (pkt, r, &metadata);
    if (ptr == NULL) {
      fprintf (stderr, "Arf\n");
      continue;
    }

    len = r - (ptr - pkt);
    if (verbose) {
      print_capture (&metadata, ptr, len, verbose);
    }

    if (fsock) {
      sendto (fsock, ptr, len, 0, (struct sockaddr *) fout,
              sizeof (struct sockaddr_ll));
    }
  }
}

void
usage (char *name)
{
  fprintf (stderr, "Usage: %s --port <udp port> --intf <forward interface> "
           "--verbose\n", name);
  exit (-1);
}

int
main (int argc, char **argv)
{
  struct option long_options[] = {
    {"intf", 1, 0, 'i'},
    {"port", 1, 0, 'p'},
    {"verbose", 0, 0, 'v'},
    {"json", 0, 0, 'j'},
    {"help", 0, 0, 'h'},
    {NULL, 0, 0, 0}
  };
  struct sockaddr_ll fout;
  int fsock = 0, usock = 0;
  int verbose = 0, a2i, c, i;
  unsigned short port = 8159;
  const char *intf;
  char *end;

  while (1) {
    c = getopt_long (argc, argv, "i:p:vjh", long_options, &i);
    if (c == -1) {
      break;
    }
    switch (c) {
    case 'i':
      intf = optarg;
      break;
    case 'p':
      a2i = strtol (optarg, &end, 10);
      if (errno == ERANGE && (a2i == LONG_MAX || a2i == LONG_MIN)) {
        fprintf (stderr, "Unable to parse the port parameter\n");
        exit(-1);
      }
      port = a2i;
      break;
    case 'v':
      if (!verbose)
          verbose = TEXT_OUTPUT;
      break;
    case 'j':
      verbose = JSON_OUTPUT;
      break;
    case 'h':
    default:
      usage (argv[0]);
    }
  }

  if ((usock = open_udp_socket (port)) == -1) {
    fprintf (stderr, "Unable to open the listening udp port: %s\n",
             strerror (errno));
    exit (-1);
  }

  if (intf != NULL) {
    if ((fsock = open_forward_socket (intf, &fout)) == -1) {
      fprintf (stderr, "Unable to open the forward interface: %s\n",
               strerror (errno));
      exit (-1);
    }
  }

  forward (usock, fsock, &fout, verbose);

  return -1;
}
