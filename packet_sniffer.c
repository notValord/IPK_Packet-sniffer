/**
 * File name:       packet_sniffer.c
 * Project:         A simple packet sniffer in C
 * Author:          Veronika Molnárová (xmolna08)
 * Date:            23.4.2022
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>

#define STR_LEN 256 // Length of string variables
#define ICMP 1  // Protocol number for ICMP packet
#define UDP 17  // Protocol number for UDP packet
#define TCP 6   // Protocol number for TCP packet

/**
 * Structure for program arguments, containing all of the possible argumetns with all necessary flags.
 * */
struct Arguments{
    char interface[STR_LEN];
    int port;
    bool is_port;
    bool tcp;
    bool udp;
    bool icmp;
    bool arp;
    bool is_specified; // if any type of packet filter is specified
    int num;
};
typedef struct Arguments Args;

/**
 * Debugging function for printing all of the parameters in the Arguments structure.
 * */
void print_args(Args* args){
    printf("Interface je %s\n", args->interface);
    printf("Port je specifikovany %d a %d\n", args->is_port, args->port);
    printf("Je tcp %d\n", args->tcp);
    printf("Je udp %d\n", args->udp);
    printf("Je icmp %d\n", args->icmp);
    printf("Je arp %d\n", args->arp);
    printf("Je vobec nieco %d\n", args->is_specified);
    printf("Pocet packetov %d\n", args->num);
}

/**
 * Function for initializing the Args structure with default values.
 * */
Args* init_args(){
    Args* args = malloc(sizeof(Args));
    strcpy(args->interface, "");
    args->port = 0;
    args->is_port = false;
    args->tcp = false;
    args->udp = false;
    args->icmp = false;
    args->arp = false;
    args->is_specified = false;
    args->num = 1;
    return args;
}

/**
 * Prints the help to the standard output, used when wrong syntax is used while trying tu run the program.
 * */
void print_help(){
    printf("Usage: ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port}"
                    " {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
    printf("\t-i or --interface => specifies the interface at which the program will be sniffing,"
                    "if the argument or the value is missing, program prints all of the possible interfaces to the stdout\n");
    printf("\t-p => specifies the port at which the program will be sniffing, if missing, program sniffs at all of the ports\n");
    printf("\t-t or --tcp => program filters for TCP packets\n");
    printf("\t-u or --udp => program filters for UDP packets\n");
    printf("\t--arp => program filters for ARP packets\n");
    printf("\t--icmp => program filters for ICMP packets\n");
    printf("\t-n => specifies the number of packets which will be shown, if missing the default value of 1 is used\n");
}


/**
 * Prints all of the found interfaces to stdout.
 * */
void print_devices(){
    pcap_if_t *alldevsp;
    char ebuff[STR_LEN];

    // this part of code was taken from the blog https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
    // written adn posted by Silver Moon on July 31, 2020,
    // modified to suit the context of the program

    if (pcap_findalldevs(&alldevsp, ebuff)){
        printf("Error finding devices : %s" , ebuff);
    }
    else{
        for(pcap_if_t *device = alldevsp ; device != NULL ; device = device->next)
        {
            // end of the taken part of the code from Silver Moon
            printf("%s\n" , device->name);
        }
    }
}

/**
 * Function for parsing the program arguments adn filling the Args structure with them.
 * */
int parse_args(int argc, char** argv, Args *args){
    int opt;
    int option_index = 0;
    static struct option long_options[] =
            {
                    {"interface",   required_argument, NULL,  0 },
                    {"tcp",         no_argument,       NULL,  0 },
                    {"udp",         no_argument,       NULL,  0 },
                    {"arp",         no_argument,       NULL,  0 },
                    {"icmp",        no_argument,       NULL,  0 },
                    {NULL,      0,              NULL,  0 }
            };

    while((opt = getopt_long(argc, argv, "-:i:p:tun:", long_options, &option_index)) != -1){
        switch(opt){
            case 0: // found long arguments
                switch (option_index) {
                    case 0: //interface
                        if (optarg)
                            strcpy(args->interface, optarg);
                        break;
                    case 1: //tcp
                        args->tcp = true;
                        args->is_specified = true;
                        break;
                    case 2: //udp
                        args->udp = true;
                        args->is_specified = true;
                        break;
                    case 3: //arp
                        args->arp = true;
                        args->is_specified = true;
                        break;
                    case 4: //icmp
                        args->icmp = true;
                        args->is_specified = true;
                        break;
                    default:
                        print_help();
                        return 1;
                }
                break;
            case 'i':
                strcpy(args->interface, optarg);
                break;
            case 'p':
                args->port = (int) strtol(optarg, NULL, 10);
                args->is_port = true;
                break;
            case 't':
                args->tcp = true;
                args->is_specified = true;
                break;
            case 'u':
                args->udp = true;
                args->is_specified = true;
                break;
            case 'n':
                args->num = (int) strtol(optarg, NULL, 10);
                break;
            case ':':
                break;
            case '?':
            case 1:
            default:
                print_help();
                return 1;
        }
    }
    if (strcmp(args->interface, "") == 0){
        print_devices();
        return 1;
    }
    return 0;
}

/**
 * Converts the time from timevalue structure to human readable form.
 * */
void print_timestamp(struct timeval tm){
    char timestamp[STR_LEN];
    struct tm *info = localtime(&tm.tv_sec);
    char usec[STR_LEN];
    sprintf(usec, "%03ld", tm.tv_usec);

    strftime(timestamp, STR_LEN, "%Y-%m-%dT%H:%M:%S", info);
    printf("timestamp: %s.%.3s+01:00\n", timestamp, usec);
}

/**
 * Prints the packets data, unprintable characters are shown as '.'.
 * */
void print_data(const u_char* packet, int length){
    int line = 0;
    char tmp[STR_LEN] = "";
    printf("\n");
    for (int i = 0; i < length; ++i) {
        if (i % 16 == 0 && i != 0){ // the end of the line
            printf(" %s\n", tmp);
            strcpy(tmp, "");
            line++;
        }

        if (i % 16 == 0){ // print the hexadecimal number of bytes read, line numbering
            printf("0x00%02d: ", line*10);
        }

        if (i % 8 == 0){ // spacing after 8 bytes
            printf(" ");
            if (strlen(tmp)){
                strcat(tmp, " ");
            }
        }

        printf("%02X ", (unsigned char) packet[i]);

        if (isprint(packet[i])) { // add to the string
            char chr = (char) packet[i];
            strcat(tmp, &chr);
        }
        else {
            strcat(tmp, ".");
        }
    }
    printf(" %s\n", tmp);
    printf("\n");
}

/**
 * Takes UDP packet and unpacks the info(port numbers) stored in it.
 * */
void take_udp_packet(const u_char* packet){
    u_int16_t *source_port = (u_int16_t*) packet;
    u_int16_t *dest_port = (u_int16_t*) (packet + sizeof(u_int16_t));

    printf("src port: %d\n", ntohs(*source_port));
    printf("dest port: %d\n", ntohs(*dest_port));
}

/**
 * Takes TCP packet and unpacks the info(ports numbers) stored in it.
 * */
void take_tcp_packet(const u_char* packet){
    struct tcphdr *tcp_header = (struct tcphdr*) packet;
    printf("src port: %d\n", ntohs(tcp_header->source));
    printf("dest port: %d\n", ntohs(tcp_header->dest));
}

/**
 * Takes ARP packet and unpacks the info(IP addresses) stored in it.
 * */
void take_arp_packet(const u_char* packet){
    struct ether_arp* arp_packet = (struct ether_arp*)(packet);
    printf("sender IP: %d.%d.%d.%d\n"
            ,arp_packet->arp_spa[0], arp_packet->arp_spa[1], arp_packet->arp_spa[2], arp_packet->arp_spa[3]);
    printf("target IP: %d.%d.%d.%d\n"
            ,arp_packet->arp_tpa[0], arp_packet->arp_tpa[1], arp_packet->arp_tpa[2], arp_packet->arp_tpa[3]);
}

/**
 * Takes IPv4 packet and unpacks the info(IP addresses) stored in it,
 * removes the header and sends it forward based on it's protocol.
 * */
void take_ip_packet(const u_char* packet){
    struct ip *ip_header = (struct ip*) packet;
    int header_len = (int) ip_header->ip_hl * 4;

    if ((int)ip_header->ip_v != 4){
        fprintf(stderr, "Problem with IPv4, wrong version\n");
        return;
    }

    printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

    if (ip_header->ip_p == ICMP){
        ; // no more data in ICMP packet which would be needed
    }
    else if(ip_header->ip_p == UDP){
        take_udp_packet(packet + header_len);
    }
    else if(ip_header->ip_p == TCP){
        take_tcp_packet(packet + header_len);
    }
}

/**
 * Takes IPv6 packet and unpacks the info(IP addresses) stored in it,
 * removes the header and sends it forward based on it's protocol.
 * */
void take_ip6_packet(const u_char* packet){
    struct ip6_hdr *ip_header = (struct ip6_hdr*) packet;
    char tmp[STR_LEN] = "";

    if (inet_ntop(AF_INET6, &ip_header->ip6_src, tmp, STR_LEN) == NULL){
        fprintf(stderr, "Error converting IPv6 IP address\n");
        return;
    }
    printf("src IP: %s\n", tmp);

    if (inet_ntop(AF_INET6, &ip_header->ip6_dst, tmp, STR_LEN) == NULL){
        fprintf(stderr, "Error converting IPv6 IP address\n");
        return;
    }
    printf("dst IP: %s\n", tmp);


    if (ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == ICMP){
        ; // no more data in ICMP packet which would be needed
    }
    else if(ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == UDP){
        take_udp_packet(packet + sizeof(struct ip6_hdr));
    }
    else if(ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == TCP){
        take_tcp_packet(packet + sizeof(struct ip6_hdr));
    }
}

/**
 * Determining the type of packet, parsing the ethernet header and printing the needed info.
 * */
void determing_packet(u_char *args, const struct pcap_pkthdr* header, const u_char* packet){
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    print_timestamp(header->ts);
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n"
            ,eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3],
            eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n"
            ,eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    printf("frame length: %d bytes\n", header->caplen);

    // determining the type of packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        take_ip_packet(packet + sizeof(struct ether_header));
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
        take_arp_packet(packet + sizeof(struct ether_header));
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6){
        take_ip6_packet(packet + sizeof(struct ether_header));
    }

    print_data(packet, (int) header->caplen);
}

/**
 * Creates the filter expression needed for the packet filter.
 * */
char* create_filter_expr(Args* args){
    char* expr = malloc(STR_LEN);
    if (!args->is_specified){
        strcpy(expr, "arp or icmp or ");
        if (args->is_port){
            char tcp[STR_LEN] = "(tcp and port ";
            char udp[STR_LEN] = "(udp and port ";
            char num[STR_LEN];
            sprintf(num, "%d", args->port);
            strcat(num, ")");
            strcat(tcp, num);
            strcat(udp, num);
            strcat(tcp, " or ");
            strcat(tcp, udp);
            strcat(expr, tcp);
        }
        else{
            strcat(expr, "tcp or udp");
        }
    }
    else{
        if (args->arp){
            strcpy(expr, "arp");
        }
        if (args->icmp){
            if (strlen(expr) == 0){
                strcpy(expr, "icmp");
            }
            else{
                strcat(expr, " or icmp");
            }
        }
        if (args->tcp){
            char tcp[STR_LEN] = "";
            if (args->is_port){
                strcat(tcp, "(tcp and port ");
                char num[STR_LEN];
                sprintf(num, "%d", args->port);
                strcat(num, ")");
                strcat(tcp, num);
            }
            else{
                strcat(tcp, "tcp");
            }
            if (strlen(expr) == 0){
                strcpy(expr, tcp);
            }
            else{
                strcat(expr, " or ");
                strcat(expr, tcp);
            }
        }
        if (args->udp){
            char udp[STR_LEN] = "";
            if (args->is_port){
                strcat(udp, "(udp and port ");
                char num[STR_LEN];
                sprintf(num, "%d", args->port);
                strcat(num, ")");
                strcat(udp, num);
            }
            else{
                strcat(udp, "udp");
            }
            if (strlen(expr) == 0){
                strcpy(expr, udp);
            }
            else{
                strcat(expr, " or ");
                strcat(expr, udp);
            }
        }
    }
    return expr;
}


/**
 * Opening the interface, creating hte filter and sniffing for the packets.
 * */

// This function was created on the image of code on https://www.tcpdump.org/pcap.html written by Tim Carstens
// Licence:
// This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification,
// are permitted provided that the following conditions are met:
//
//  1. Redistribution must retain the above copyright notice and this list of conditions.
//  2. The name of Tim Carstens may not be used to endorse or promote products derived from this document
//      without specific prior written permission.
//
//  All rights are reserved to the Tim Carstens.

int sniff(Args* args){
    char ebuff[STR_LEN];
    char* f_expr = create_filter_expr(args);
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t* handle;


    if (pcap_lookupnet(args->interface, &net, &mask, ebuff) == -1) {
        fprintf(stderr, "Can't get netmask, %s\n", ebuff);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(args->interface, BUFSIZ, 1, 0, ebuff);
    if (handle == NULL){
        fprintf(stderr, "Couldn't open interface, %s\n", ebuff);
        free(f_expr);
        return 2;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "The interface doesn't support ethernet\n");
        free(f_expr);
        return 0;
    }

    // Creates the filter
    if (pcap_compile(handle, &fp, f_expr, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter\n");
        free(f_expr);
        return(3);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter\n");
        free(f_expr);
        return(3);
    }

    /* Grab a packet */
    pcap_loop(handle, args->num, determing_packet, NULL);
    pcap_close(handle);
    free(f_expr);
    return 0;
}

/**
 * Function to handle the Ctrl + C kill signal.
 * */
void sighandle(){
    printf("Killing the proccess...\n");
    exit(3);
}

int main(int argc, char** argv) {
    signal(SIGINT, sighandle);
    Args* args = init_args();
    int failed = parse_args(argc, argv, args);
    if (failed){
        free(args);
        return 1;
    }
    failed = sniff(args);

    free(args);
    return failed;
}
