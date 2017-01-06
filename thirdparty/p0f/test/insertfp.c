/**
 * Unit test for p0f
 * Insert finger print record to database after read from a pcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "../p0f.h"

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char *packet);

int main(int argc, char **argv)
{
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    p0fhdlr *hdlr = p0f_init(NULL);
    descr = pcap_open_offline(argv[1], errbuf);
    if (descr == NULL) {
        printf("Pcap file open failed");
        goto err;
    }

    int linktype = pcap_datalink(descr);
    p0f_set_linktype(hdlr, linktype);
    
    if (pcap_loop(descr, 0, packetHandler, (u_char *)hdlr) < 0) {
        printf("pcap_loop() failed\n");
        goto err;
    }
    
    pcap_close(descr);
    p0f_close(hdlr);
    return 0;
err:
    pcap_close(descr);
    p0f_close(hdlr);
    return -1;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
    parse_packet(userData, pkthdr, packet, NULL);
}
