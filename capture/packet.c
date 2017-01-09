/* packet.c  -- Functions for acquiring data
 *
 * Copyright 2012-2016 AOL Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this Software except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "moloch.h"
#include <inttypes.h>
#include <arpa/inet.h>
#ifdef USE_SPSC_RING
#include "spsc_ring.h"
#endif

//#define DEBUG_PACKET

/******************************************************************************/
extern MolochConfig_t        config;

MolochPcapFileHdr_t          pcapFileHeader;

uint64_t                     totalPackets = 0;
uint64_t                     totalBytes = 0;
uint64_t                     totalSessions = 0;

LOCAL uint32_t               initialDropped = 0;
struct timeval               initialPacket;

extern void                 *esServer;
extern uint32_t              pluginsCbs;

LOCAL int                    mac1Field;
LOCAL int                    mac2Field;
LOCAL int                    vlanField;
LOCAL int                    greIpField;

LOCAL uint64_t               droppedFrags;

time_t                       lastPacketSecs[MOLOCH_MAX_PACKET_THREADS];

/******************************************************************************/
extern MolochSessionHead_t   tcpWriteQ[MOLOCH_MAX_PACKET_THREADS];

#ifdef USE_SPSC_RING
struct pkt_thread_st {
        char wait_pkt;
        int thread_id;
        struct spsc_ring_st *r;
        uint64_t dequeue_num;
};
LOCAL struct pkt_thread_st   spsc_pktq[MOLOCH_MAX_PACKET_THREADS];
#else
LOCAL  MolochPacketHead_t    packetQ[MOLOCH_MAX_PACKET_THREADS];
#endif
LOCAL  uint32_t              overloadDrops[MOLOCH_MAX_PACKET_THREADS];

LOCAL  MolochPacketHead_t    fragsQ;

LOCAL  gboolean              callFilters;


int moloch_packet_ip4(MolochPacket_t * const packet, const uint8_t *data, int len);

typedef struct molochfrags_t {
    struct molochfrags_t  *fragh_next, *fragh_prev;
    struct molochfrags_t  *fragl_next, *fragl_prev;
    uint32_t               fragh_bucket;
    uint32_t               fragh_hash;
    MolochPacketHead_t     packets;
    char                   key[10];
    uint32_t               secs;
    char                   haveNoFlags;
} MolochFrags_t;

typedef struct {
    struct molochfrags_t  *fragh_next, *fragh_prev;
    struct molochfrags_t  *fragl_next, *fragl_prev;
    short                  fragh_bucket;
    uint32_t               fragh_count;
    uint32_t               fragl_count;
} MolochFragsHead_t;

typedef HASH_VAR(h_, MolochFragsHash_t, MolochFragsHead_t, 199337);

MolochFragsHash_t          fragsHash;
MolochFragsHead_t          fragsList;

/******************************************************************************/
void moloch_packet_free(MolochPacket_t *packet)
{
    if (packet->copied) {
        free(packet->pkt);
    }
    packet->pkt = 0;
    MOLOCH_TYPE_FREE(MolochPacket_t, packet);
}
/******************************************************************************/
void moloch_packet_tcp_free(MolochSession_t *session)
{
    MolochTcpData_t *td;
    while (DLL_POP_HEAD(td_, &session->tcpData, td)) {
        moloch_packet_free(td->packet);
        MOLOCH_TYPE_FREE(MolochTcpData_t, td);
    }
}
/******************************************************************************/
// Idea from gopacket tcpassembly/assemply.go
LOCAL int32_t moloch_packet_sequence_diff (uint32_t a, uint32_t b)
{
    if (a > 0xc0000000 && b < 0x40000000)
        return (a + 0xffffffffLL - b);

    if (b > 0xc0000000 && a < 0x40000000)
        return (a - b - 0xffffffffLL);

    return b - a;
}
/******************************************************************************/
void moloch_packet_process_data(MolochSession_t *session, const uint8_t *data, int len, int which)
{
    int i;
    int totConsumed = 0;
    int consumed = 0;

    for (i = 0; i < session->parserNum; i++) {
        if (session->parserInfo[i].parserFunc) {
            consumed = session->parserInfo[i].parserFunc(session, session->parserInfo[i].uw, data, len, which);
            if (consumed) {
                totConsumed += consumed;
                session->consumed[which] += consumed;
            }

            if (consumed >= len)
                break;
        }
    }
}
/******************************************************************************/
void moloch_packet_tcp_finish(MolochSession_t *session)
{
    MolochTcpData_t            *ftd;
    MolochTcpData_t            *next;

    MolochTcpDataHead_t * const tcpData = &session->tcpData;

#ifdef DEBUG_PACKET
    LOG("START");
    DLL_FOREACH(td_, tcpData, ftd) {
        LOG("dir: %d seq: %8u ack: %8u len: %4u", ftd->packet->direction, ftd->seq, ftd->ack, ftd->len);
    }
#endif

    DLL_FOREACH_REMOVABLE(td_, tcpData, ftd, next) {
        const int which = ftd->packet->direction;
        const uint32_t tcpSeq = session->tcpSeq[which];

        if (tcpSeq >= ftd->seq && tcpSeq < (ftd->seq + ftd->len)) {
            const int offset = tcpSeq - ftd->seq;
            const uint8_t *data = ftd->packet->pkt + ftd->dataOffset + offset;
            const int len = ftd->len - offset;

            if (session->firstBytesLen[which] < 8) {
                int copy = MIN(8 - session->firstBytesLen[which], len);
                memcpy(session->firstBytes[which] + session->firstBytesLen[which], data, copy);
                session->firstBytesLen[which] += copy;
            }

            if (session->totalDatabytes[which] == session->consumed[which])  {
                moloch_parsers_classify_tcp(session, data, len, which);
            }

            moloch_packet_process_data(session, data, len, which);
            session->tcpSeq[which] += len;
            session->databytes[which] += len;
            session->totalDatabytes[which] += len;

            if (config.yara) {
                moloch_yara_execute(session, data, len, 0);
            }

            DLL_REMOVE(td_, tcpData, ftd);
            moloch_packet_free(ftd->packet);
            MOLOCH_TYPE_FREE(MolochTcpData_t, ftd);
        } else {
            return;
        }
    }
}

/******************************************************************************/
void moloch_packet_process_icmp(MolochSession_t * const UNUSED(session), MolochPacket_t * const UNUSED(packet))
{
}
/******************************************************************************/
void moloch_packet_process_udp(MolochSession_t * const session, MolochPacket_t * const packet)
{
    const uint8_t *data = packet->pkt + packet->payloadOffset + 8;
    int            len = packet->payloadLen - 8;

    if (len <= 0)
        return;

    if (session->firstBytesLen[packet->direction] == 0) {
        session->firstBytesLen[packet->direction] = MIN(8, len);
        memcpy(session->firstBytes[packet->direction], data, session->firstBytesLen[packet->direction]);

        if (!session->stopSPI)
            moloch_parsers_classify_udp(session, data, len, packet->direction);
    }

    int i;
    for (i = 0; i < session->parserNum; i++) {
        if (session->parserInfo[i].parserFunc) {
            session->parserInfo[i].parserFunc(session, session->parserInfo[i].uw, data, len, packet->direction);
        }
    }
}
/******************************************************************************/
int moloch_packet_process_tcp(MolochSession_t * const session, MolochPacket_t * const packet)
{
    if (session->stopSPI || session->stopTCP)
        return 1;

    struct tcphdr       *tcphdr = (struct tcphdr *)(packet->pkt + packet->payloadOffset);


    int            len = packet->payloadLen - 4*tcphdr->th_off;

#ifdef DEBUG_PACKET
    LOG("poffset: %d plen: %d len: %d", packet->payloadOffset, packet->payloadLen, len);
#endif

    const uint32_t seq = ntohl(tcphdr->th_seq);

    if (len < 0)
        return 1;

    if (tcphdr->th_flags & TH_SYN) {
        session->haveTcpSession = 1;
        session->tcpSeq[packet->direction] = seq + 1;
        if (!session->tcp_next) {
            DLL_PUSH_TAIL(tcp_, &tcpWriteQ[session->thread], session);
        }
        return 1;
    }

    if (tcphdr->th_flags & TH_RST) {
        if (moloch_packet_sequence_diff(seq, session->tcpSeq[packet->direction]) <= 0) {
            return 1;
        }

        session->tcpState[packet->direction] = MOLOCH_TCP_STATE_FIN_ACK;
    }

    if (tcphdr->th_flags & TH_FIN) {
        session->tcpState[packet->direction] = MOLOCH_TCP_STATE_FIN;
    }

    MolochTcpDataHead_t * const tcpData = &session->tcpData;

    if (DLL_COUNT(td_, tcpData) > 256) {
        moloch_packet_tcp_free(session);
        moloch_session_add_tag(session, "incomplete-tcp");
        session->stopTCP = 1;
        return 1;
    }

    if (tcphdr->th_flags & (TH_ACK | TH_RST)) {
        int owhich = (packet->direction + 1) & 1;
        if (session->tcpState[owhich] == MOLOCH_TCP_STATE_FIN) {
            session->tcpState[owhich] = MOLOCH_TCP_STATE_FIN_ACK;
            if (session->tcpState[packet->direction] == MOLOCH_TCP_STATE_FIN_ACK) {

                if (!session->closingQ) {
                    moloch_session_mark_for_close(session, SESSION_TCP);
                }
                return 1;
            }
        }
    }

    // Empty packet, drop from tcp processing
    if (len <= 0 || tcphdr->th_flags & TH_RST)
        return 1;

    // This packet is before what we are processing
    int32_t diff = moloch_packet_sequence_diff(session->tcpSeq[packet->direction], seq + len);
    if (diff <= 0)
        return 1;

    MolochTcpData_t *ftd, *td = MOLOCH_TYPE_ALLOC(MolochTcpData_t);
    const uint32_t ack = ntohl(tcphdr->th_ack);

    td->packet = packet;
    td->ack = ack;
    td->seq = seq;
    td->len = len;
    td->dataOffset = packet->payloadOffset + 4*tcphdr->th_off;

    if (DLL_COUNT(td_, tcpData) == 0) {
        DLL_PUSH_TAIL(td_, tcpData, td);
    } else {
        uint32_t sortA, sortB;
        DLL_FOREACH_REVERSE(td_, tcpData, ftd) {
            if (packet->direction == ftd->packet->direction) {
                sortA = seq;
                sortB = ftd->seq;
            } else {
                sortA = seq;
                sortB = ftd->ack;
            }

            diff = moloch_packet_sequence_diff(sortB, sortA);
            if (diff == 0) {
                if (packet->direction == ftd->packet->direction) {
                    if (td->len > ftd->len) {
                        DLL_ADD_AFTER(td_, tcpData, ftd, td);

                        DLL_REMOVE(td_, tcpData, ftd);
                        moloch_packet_free(ftd->packet);
                        MOLOCH_TYPE_FREE(MolochTcpData_t, ftd);
                        ftd = td;
                    } else {
                        MOLOCH_TYPE_FREE(MolochTcpData_t, td);
                        return 1;
                    }
                    break;
                } else if (moloch_packet_sequence_diff(ack, ftd->seq) < 0) {
                    DLL_ADD_AFTER(td_, tcpData, ftd, td);
                    break;
                }
            } else if (diff > 0) {
                DLL_ADD_AFTER(td_, tcpData, ftd, td);
                break;
            }
        }
        if ((void*)ftd == (void*)tcpData) {
            DLL_PUSH_HEAD(td_, tcpData, td);
        }
    }

    return 0;
}

/******************************************************************************/
void moloch_packet_thread_wake(int thread)
{
#ifdef USE_SPSC_RING
    spsc_pktq[thread].wait_pkt = 0;
#else
    MOLOCH_LOCK(packetQ[thread].lock);
    MOLOCH_COND_SIGNAL(packetQ[thread].lock);
    MOLOCH_UNLOCK(packetQ[thread].lock);
#endif
}
/******************************************************************************/
/* Only called on main thread, we busy block until all packet threads are empty.
 * Should only be used by tests and at end
 */
void moloch_packet_flush()
{
    int flushed = 0;
    int t;
    while (!flushed) {
        flushed = !moloch_session_cmd_outstanding();

        for (t = 0; t < config.packetThreads; t++) {
#ifdef USE_SPSC_RING
	    if(spsc_ring_count(spsc_pktq[t].r) > 0) {
                flushed = 0;
            }
#else
            MOLOCH_LOCK(packetQ[t].lock);
            if (DLL_COUNT(packet_, &packetQ[t]) > 0) {
                flushed = 0;
            }
            MOLOCH_UNLOCK(packetQ[t].lock);
#endif
            usleep(10000);
        }
    }
}
/******************************************************************************/
LOCAL void *moloch_packet_thread(void *threadp)
{
#ifdef USE_SPSC_RING
    int deq_ret = 0;
    void *deq_data = NULL;
#endif
    MolochPacket_t  *packet;
    int thread = (long)threadp;

#ifdef USE_SCHED_AFFINITY
    LOG("tid : %ld", pthread_self());
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(config.cpuAffinityStart + 1 + thread, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
    LOG("thread %d affinity set to %d", thread, config.cpuAffinityStart + 1 + thread);
#endif

    while (1) {
#ifdef USE_SPSC_RING
	while(spsc_pktq[thread].wait_pkt) usleep(1);

        deq_ret = spsc_ring_dequeue(spsc_pktq[thread].r, &deq_data);

        if (deq_ret < 0) {
                spsc_pktq[thread].wait_pkt = 1;
		moloch_session_process_commands(thread);

                continue;
        }
        else {
            packet = (MolochPacket_t *)deq_data;
            spsc_pktq[thread].dequeue_num++;
        }
#else
        MOLOCH_LOCK(packetQ[thread].lock);
        if (DLL_COUNT(packet_, &packetQ[thread]) == 0) {
            struct timeval tv;
            struct timespec ts;
            gettimeofday(&tv, NULL);
            ts.tv_sec = tv.tv_sec + 1;
            ts.tv_nsec = 0;
            MOLOCH_COND_TIMEDWAIT(packetQ[thread].lock, ts);
        }
        DLL_POP_HEAD(packet_, &packetQ[thread], packet);
        MOLOCH_UNLOCK(packetQ[thread].lock);
#endif

        moloch_session_process_commands(thread);

        if (!packet)
            continue;

        lastPacketSecs[thread] = packet->ts.tv_sec;

        MolochSession_t     *session;
        struct ip           *ip4 = (struct ip*)(packet->pkt + packet->ipOffset);
        struct ip6_hdr      *ip6 = (struct ip6_hdr*)(packet->pkt + packet->ipOffset);
        struct tcphdr       *tcphdr = 0;
        struct udphdr       *udphdr = 0;
#ifdef USE_ONE_SSID
	char		     *sessionId = packet->sessionId;
#else
        char                 sessionId[MOLOCH_SESSIONID_LEN];
#endif

        switch (packet->protocol) {
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *)(packet->pkt + packet->payloadOffset);

#ifndef USE_ONE_SSID
            if (packet->v6) {
                moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, tcphdr->th_sport,
                                   ip6->ip6_dst.s6_addr, tcphdr->th_dport);
            } else {
                moloch_session_id(sessionId, ip4->ip_src.s_addr, tcphdr->th_sport,
                                  ip4->ip_dst.s_addr, tcphdr->th_dport);
            }
#endif
            break;
        case IPPROTO_UDP:
            udphdr = (struct udphdr *)(packet->pkt + packet->payloadOffset);
#ifndef USE_ONE_SSID
            if (packet->v6) {
                moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, udphdr->uh_sport,
                                   ip6->ip6_dst.s6_addr, udphdr->uh_dport);
            } else {
                moloch_session_id(sessionId, ip4->ip_src.s_addr, udphdr->uh_sport,
                                  ip4->ip_dst.s_addr, udphdr->uh_dport);
            }
#endif
            break;
#ifndef USE_ONE_SSID
        case IPPROTO_ICMP:
            if (packet->v6) {
                moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, 0,
                                   ip6->ip6_dst.s6_addr, 0);
            } else {
                moloch_session_id(sessionId, ip4->ip_src.s_addr, 0,
                                  ip4->ip_dst.s_addr, 0);
            }
            break;
        case IPPROTO_ICMPV6:
            moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, 0,
                               ip6->ip6_dst.s6_addr, 0);
            break;
#endif
        }

        int isNew;
#ifdef USE_ONE_SSID
        session = moloch_session_find_or_create(packet, &isNew); // Returns locked session
#else
        session = moloch_session_find_or_create(packet->ses,sessionId, &isNew); // Returns locked session
#endif

        if (isNew) {
            session->saveTime = packet->ts.tv_sec + config.tcpSaveTimeout;
            session->firstPacket = packet->ts;

            session->protocol = packet->protocol;
            if (ip4->ip_v == 4) {
                ((uint32_t *)session->addr1.s6_addr)[2] = htonl(0xffff);
                ((uint32_t *)session->addr1.s6_addr)[3] = ip4->ip_src.s_addr;
                ((uint32_t *)session->addr2.s6_addr)[2] = htonl(0xffff);
                ((uint32_t *)session->addr2.s6_addr)[3] = ip4->ip_dst.s_addr;
                session->ip_tos = ip4->ip_tos;
            } else {
                session->addr1 = ip6->ip6_src;
                session->addr2 = ip6->ip6_dst;
                session->ip_tos = 0;
            }
            session->thread = thread;

            moloch_parsers_initial_tag(session);

            switch (session->protocol) {
            case IPPROTO_TCP:
               /* If antiSynDrop option is set to true, capture will assume that
                *if the syn-ack ip4 was captured first then the syn probably got dropped.*/
                if ((tcphdr->th_flags & TH_SYN) && (tcphdr->th_flags & TH_ACK) && (config.antiSynDrop)) {
                    struct in6_addr tmp;
                    tmp = session->addr1;
                    session->addr1 = session->addr2;
                    session->addr2 = tmp;
                    session->port1 = ntohs(tcphdr->th_dport);
                    session->port2 = ntohs(tcphdr->th_sport);
                } else {
                    session->port1 = ntohs(tcphdr->th_sport);
                    session->port2 = ntohs(tcphdr->th_dport);
                }
                if (moloch_http_is_moloch(session->h_hash, sessionId)) {
                    if (config.debug) {
                        char buf[1000];
                        LOG("Ignoring connection %s", moloch_session_id_string(session->sessionId, buf));
                    }
                    session->stopSPI = 1;
                    session->stopSaving = 1;
                }
                break;
            case IPPROTO_UDP:
                session->port1 = ntohs(udphdr->uh_sport);
                session->port2 = ntohs(udphdr->uh_dport);
                break;
            case IPPROTO_ICMP:
                break;
            }

            if (pluginsCbs & MOLOCH_PLUGIN_NEW)
                moloch_plugins_cb_new(session);
        }

        int dir;
        if (ip4->ip_v == 4) {
            dir = (MOLOCH_V6_TO_V4(session->addr1) == ip4->ip_src.s_addr &&
                   MOLOCH_V6_TO_V4(session->addr2) == ip4->ip_dst.s_addr);
        } else {
            dir = (memcmp(session->addr1.s6_addr, ip6->ip6_src.s6_addr, 16) == 0 &&
                   memcmp(session->addr2.s6_addr, ip6->ip6_dst.s6_addr, 16) == 0);
        }

        packet->direction = 0;
        switch (session->protocol) {
        case IPPROTO_UDP:
            udphdr = (struct udphdr *)(packet->pkt + packet->payloadOffset);
            packet->direction = (dir &&
                                 session->port1 == ntohs(udphdr->uh_sport) &&
                                 session->port2 == ntohs(udphdr->uh_dport))?0:1;
            session->databytes[packet->direction] += (packet->pktlen - 8);
            break;
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *)(packet->pkt + packet->payloadOffset);
            packet->direction = (dir &&
                                 session->port1 == ntohs(tcphdr->th_sport) &&
                                 session->port2 == ntohs(tcphdr->th_dport))?0:1;
            session->tcp_flags |= tcphdr->th_flags;
            break;
        case IPPROTO_ICMP:
            packet->direction = (dir)?0:1;
            break;
        }

        /* Check if the stop saving bpf filters match */
        if (session->packets[packet->direction] == 0 && session->stopSaving == 0 && callFilters) {
            if (moloch_reader_should_filter) {
                enum MolochFilterType type;
                int index;
                if (moloch_reader_should_filter(packet, &type, &index)) {
                    if (type == MOLOCH_FILTER_DONT_SAVE)
                        session->stopSaving = config.bpfsVal[type][index];
                    else if (type == MOLOCH_FILTER_MIN_SAVE)
                        session->minSaving = config.bpfsVal[type][index];
                }
            }
        }

        session->packets[packet->direction]++;
        session->bytes[packet->direction] += packet->pktlen;
        session->lastPacket = packet->ts;

        uint32_t packets = session->packets[0] + session->packets[1];

        if (session->stopSaving == 0 || packets < session->stopSaving) {
            moloch_writer_write(session, packet);

            int16_t len;
            if (session->lastFileNum != packet->writerFileNum) {
                session->lastFileNum = packet->writerFileNum;
                g_array_append_val(session->fileNumArray, packet->writerFileNum);
                int64_t pos = -1LL * packet->writerFileNum;
                g_array_append_val(session->filePosArray, pos);
                len = 0;
                g_array_append_val(session->fileLenArray, len);
            }

            g_array_append_val(session->filePosArray, packet->writerFilePos);
            len = 16 + packet->pktlen;
            g_array_append_val(session->fileLenArray, len);

            if (packets >= config.maxPackets || session->midSave) {
                moloch_session_mid_save(session, packet->ts.tv_sec);
            }
        }

        if (pcapFileHeader.linktype == 1 && session->firstBytesLen[packet->direction] < 8 && session->packets[packet->direction] < 10) {
            const uint8_t *pcapData = packet->pkt;
            char str1[20];
            char str2[20];
            snprintf(str1, sizeof(str1), "%02x:%02x:%02x:%02x:%02x:%02x",
                    pcapData[0],
                    pcapData[1],
                    pcapData[2],
                    pcapData[3],
                    pcapData[4],
                    pcapData[5]);


            snprintf(str2, sizeof(str2), "%02x:%02x:%02x:%02x:%02x:%02x",
                    pcapData[6],
                    pcapData[7],
                    pcapData[8],
                    pcapData[9],
                    pcapData[10],
                    pcapData[11]);

            if (packet->direction == 1) {
                moloch_field_string_add(mac1Field, session, str1, 17, TRUE);
                moloch_field_string_add(mac2Field, session, str2, 17, TRUE);
            } else {
                moloch_field_string_add(mac1Field, session, str2, 17, TRUE);
                moloch_field_string_add(mac2Field, session, str1, 17, TRUE);
            }

            int n = 12;
            while (pcapData[n] == 0x81 && pcapData[n+1] == 0x00) {
                uint16_t vlan = ((uint16_t)(pcapData[n+2] << 8 | pcapData[n+3])) & 0xfff;
                moloch_field_int_add(vlanField, session, vlan);
                n += 4;
            }

            if (packet->vpnIpOffset) {
                ip4 = (struct ip*)(packet->pkt + packet->vpnIpOffset);
                moloch_field_int_add(greIpField, session, ip4->ip_src.s_addr);
                moloch_field_int_add(greIpField, session, ip4->ip_dst.s_addr);
                moloch_session_add_protocol(session, "gre");
            }
        }


        int freePacket = 1;
        switch(packet->ses) {
        case SESSION_ICMP:
            moloch_packet_process_icmp(session, packet);
            break;
        case SESSION_UDP:
            moloch_packet_process_udp(session, packet);
            break;
        case SESSION_TCP:
            freePacket = moloch_packet_process_tcp(session, packet);
            fingerprint_tcp(session, packet);
            moloch_packet_tcp_finish(session);
            break;
        }

        if (freePacket) {
            moloch_packet_free(packet);
        }
    }

    return NULL;
}

/******************************************************************************/
int moloch_packet_ip4(MolochPacket_t * const packet, const uint8_t *data, int len);
int moloch_packet_gre4(MolochPacket_t * const packet, const uint8_t *data, int len)
{
    BSB bsb;

    if (len < 4)
        return 1;

    BSB_INIT(bsb, data, len);
    uint16_t flags_version = 0;
    BSB_IMPORT_u16(bsb, flags_version);
    uint16_t type = 0;
    BSB_IMPORT_u16(bsb, type);

    if (type != 0x0800) {
        if (config.logUnknownProtocols)
            LOG("Unknown GRE protocol 0x%04x(%d)", type, type);
        return 1;
    }

    uint16_t UNUSED(offset) = 0;

    if (flags_version & (0x8000 | 0x4000)) {
        BSB_IMPORT_skip(bsb, 2);
        BSB_IMPORT_u16(bsb, offset);
    }

    // key
    if (flags_version & 0x2000) {
        BSB_IMPORT_skip(bsb, 4);
    }

    // sequence number
    if (flags_version & 0x1000) {
        BSB_IMPORT_skip(bsb, 4);
    }

    // routing
    if (flags_version & 0x4000) {
        while (BSB_NOT_ERROR(bsb)) {
            BSB_IMPORT_skip(bsb, 3);
            int len = 0;
            BSB_IMPORT_u08(bsb, len);
            if (len == 0)
                break;
            BSB_IMPORT_skip(bsb, len);
        }
    }

    if (BSB_IS_ERROR(bsb)) 
        return 1;

    return moloch_packet_ip4(packet, BSB_WORK_PTR(bsb), BSB_REMAINING(bsb));
}
/******************************************************************************/
void moloch_packet_frags_free(MolochFrags_t * const frags)
{
    MolochPacket_t *packet;

    while (DLL_POP_HEAD(packet_, &frags->packets, packet)) {
        moloch_packet_free(packet);
    }
    HASH_REMOVE(fragh_, fragsHash, frags);
    DLL_REMOVE(fragl_, &fragsList, frags);
    MOLOCH_TYPE_FREE(MolochFrags_t, frags);
}
/******************************************************************************/
void moloch_packet_frags_process(MolochPacket_t * const packet)
{
    MolochPacket_t * fpacket;
    MolochFrags_t   *frags;
    char             key[10];

    struct ip * const ip4 = (struct ip*)(packet->pkt + packet->ipOffset);
    memcpy(key, &ip4->ip_src.s_addr, 4);
    memcpy(key+4, &ip4->ip_dst.s_addr, 4);
    memcpy(key+8, &ip4->ip_id, 2);

    HASH_FIND(fragh_, fragsHash, key, frags);

    if (!frags) {
        frags = MOLOCH_TYPE_ALLOC0(MolochFrags_t);
        memcpy(frags->key, key, 10);
        frags->secs = packet->ts.tv_sec;
        HASH_ADD(fragh_, fragsHash, key, frags);
        DLL_PUSH_TAIL(fragl_, &fragsList, frags);
        DLL_INIT(packet_, &frags->packets);
        DLL_PUSH_TAIL(packet_, &frags->packets, packet);

        if (DLL_COUNT(fragl_, &fragsList) > config.maxFrags) {
            droppedFrags++;
            moloch_packet_frags_free(DLL_PEEK_HEAD(fragl_, &fragsList));
        }
        return;
    } else {
        DLL_MOVE_TAIL(fragl_, &fragsList, frags);
    }

    uint16_t          ip_off = ntohs(ip4->ip_off);
    uint16_t          ip_flags = ip_off & ~IP_OFFMASK;
    ip_off &= IP_OFFMASK;

    // we might be done once we receive the packets with no flags
    if (ip_flags == 0) {
        frags->haveNoFlags = 1;
    }

    // Insert this packet in correct location sorted by offset
    DLL_FOREACH_REVERSE(packet_, &frags->packets, fpacket) {
        struct ip *fip4 = (struct ip*)(fpacket->pkt + fpacket->ipOffset);
        uint16_t fip_off = ntohs(fip4->ip_off) & IP_OFFMASK;
        if (ip_off >= fip_off) {
            DLL_ADD_AFTER(packet_, &frags->packets, fpacket, packet);
            break;
        }
    }
    if ((void*)fpacket == (void*)&frags->packets) {
        DLL_PUSH_HEAD(packet_, &frags->packets, packet);
    }

    // Don't bother checking until we get a packet with no flags
    if (!frags->haveNoFlags) {
        return;
    }

    int off = 0;
    struct ip *fip4;
    uint16_t fip_off;

    int payloadLen = 0;
    DLL_FOREACH(packet_, &frags->packets, fpacket) {
        fip4 = (struct ip*)(fpacket->pkt + fpacket->ipOffset);
        fip_off = ntohs(fip4->ip_off) & IP_OFFMASK;
        if (fip_off != off)
            break;
        off += fpacket->payloadLen/8;
        payloadLen = MAX(payloadLen, fip_off*8 + fpacket->payloadLen);
    }
    // We have a hole
    if ((void*)fpacket != (void*)&frags->packets) {
        return;
    }

    // Packet is too large, hacker
    if (payloadLen + packet->payloadOffset >= MOLOCH_PACKET_MAX_LEN) {
        droppedFrags++;
        moloch_packet_frags_free(frags);
        return;
    }

    // Now alloc the full packet
    packet->pktlen = packet->payloadOffset + payloadLen;
    uint8_t *pkt = malloc(packet->pktlen);
    memcpy(pkt, packet->pkt, packet->payloadOffset);

    // Fix header of new packet
    fip4 = (struct ip*)(pkt + packet->ipOffset);
    fip4->ip_len = htons(payloadLen + 4*ip4->ip_hl);
    fip4->ip_off = 0;

    // Copy payload
    DLL_FOREACH(packet_, &frags->packets, fpacket) {
        struct ip *fip4 = (struct ip*)(fpacket->pkt + fpacket->ipOffset);
        uint16_t fip_off = ntohs(fip4->ip_off) & IP_OFFMASK;

        memcpy(pkt+packet->payloadOffset+(fip_off*8), fpacket->pkt+fpacket->payloadOffset, fpacket->payloadLen);
    }

    // Set all the vars in the current packet to new defraged packet
    if (packet->copied)
        free(packet->pkt);
    packet->pkt = pkt;
    packet->copied = 1;
    packet->wasfrag = 1;
    packet->payloadLen = payloadLen;
    DLL_REMOVE(packet_, &frags->packets, packet); // Remove from list so we don't get freed
    moloch_packet_frags_free(frags);

    moloch_packet(packet);
}
/******************************************************************************/
LOCAL void *moloch_packet_frags_thread(void *UNUSED(unused))
{
    MolochPacket_t  *packet;
    MolochFrags_t   *frags;


    while (1) {
        MOLOCH_LOCK(fragsQ.lock);
        while (DLL_COUNT(packet_, &fragsQ) == 0) {
            MOLOCH_COND_WAIT(fragsQ.lock);
        }
        DLL_POP_HEAD(packet_, &fragsQ, packet);
        MOLOCH_UNLOCK(fragsQ.lock);


        // Remove expired entries
        while ((frags = DLL_PEEK_HEAD(fragl_, &fragsList)) && (frags->secs + config.fragsTimeout < packet->ts.tv_sec)) {
            droppedFrags++;
            moloch_packet_frags_free(frags);
        }

        moloch_packet_frags_process(packet);
    }
    return NULL;
}
/******************************************************************************/
void moloch_packet_frags4(MolochPacket_t * const packet)
{
    uint8_t *pkt = malloc(packet->pktlen);
    memcpy(pkt, packet->pkt, packet->pktlen);
    packet->pkt = pkt;
    packet->copied = 1;

    // When running tests we do on the same thread so results are more determinstic
    if (config.tests) {
        moloch_packet_frags_process(packet);
        return;
    }


    MOLOCH_LOCK(fragsQ.lock);
    DLL_PUSH_TAIL(packet_, &fragsQ, packet);
    MOLOCH_COND_SIGNAL(fragsQ.lock);
    MOLOCH_UNLOCK(fragsQ.lock);
}
/******************************************************************************/
int moloch_packet_frags_size()
{
    return DLL_COUNT(fragl_, &fragsList);
}
/******************************************************************************/
int moloch_packet_frags_outstanding()
{
    return DLL_COUNT(packet_, &fragsQ);
}
/******************************************************************************/
#ifdef USE_ONE_SSID
int moloch_packet_ip(MolochPacket_t * const packet)
#else
int moloch_packet_ip(MolochPacket_t * const packet, const char * const sessionId)
#endif
{
    totalBytes += packet->pktlen;

    if (totalPackets == 0) {
        MolochReaderStats_t stats;
        if (!moloch_reader_stats(&stats)) {
            initialDropped = stats.dropped;
        }
        initialPacket = packet->ts;
        LOG("Initial Packet = %ld", initialPacket.tv_sec);
        LOG("%" PRIu64 " Initial Dropped = %d", totalPackets, initialDropped);
    }

#ifdef USE_CHECK_STATS
    if ((++totalPackets) % config.logEveryXPackets == 0) {
        MolochReaderStats_t stats;
        if (moloch_reader_stats(&stats)) {
            stats.dropped = 0;
            stats.total = totalPackets;
        }

        LOG("packets: %" PRIu64 " current sessions: %u/%u oldest: %d - recv: %" PRIu64 " drop: %" PRIu64 " (%0.2f) queue: %d disk: %d packet: %d close: %d ns: %d frags: %d/%d",
          totalPackets,
          moloch_session_watch_count(packet->ses),
          moloch_session_monitoring(),
          moloch_session_idle_seconds(packet->ses),
          stats.total,
          stats.dropped - initialDropped,
          (stats.dropped - initialDropped)*(double)100.0/stats.total,
          moloch_http_queue_length(esServer),
          moloch_writer_queue_length(),
          moloch_packet_outstanding(),
          moloch_session_close_outstanding(),
          moloch_session_need_save_outstanding(),
          moloch_packet_frags_outstanding(),
          moloch_packet_frags_size()
          );
    }
#else
    totalPackets++;
#endif

#ifdef USE_ONE_SSID
    packet->hash = moloch_session_hash(packet->sessionId);
    uint32_t thread = packet->hash % config.packetThreads;
#else
    uint32_t thread = moloch_session_hash(sessionId) % config.packetThreads;
#endif

#ifndef USE_SPSC_RING
    if (DLL_COUNT(packet_, &packetQ[thread]) >= config.maxPacketsInQueue) {
        MOLOCH_LOCK(packetQ[thread].lock);
        overloadDrops[thread]++;
        if ((overloadDrops[thread] % 1000) == 1) {
            LOG("WARNING - Packet Q %d is overflowing, total dropped %u, increase packetThreads or maxPacketsInQueue", thread, overloadDrops[thread]);
        }
        packet->pkt = 0;
        MOLOCH_COND_SIGNAL(packetQ[thread].lock);
        MOLOCH_UNLOCK(packetQ[thread].lock);
        return 1;
    }
#endif

    if (!packet->copied) {
        uint8_t *pkt = malloc(packet->pktlen);
        memcpy(pkt, packet->pkt, packet->pktlen);
        packet->pkt = pkt;
        packet->copied = 1;
    }

#ifdef USE_SPSC_RING
    if (spsc_ring_enqueue(spsc_pktq[thread].r, packet) < 0) {
	free(packet->pkt);
	packet->pkt = 0;
	printf("spsc_ring_enqueue failed : %d\n", spsc_ring_count(spsc_pktq[thread].r));
    	return 1;
    }
    else if(spsc_pktq[thread].wait_pkt) spsc_pktq[thread].wait_pkt = 0;
#else
    MOLOCH_LOCK(packetQ[thread].lock);
    DLL_PUSH_TAIL(packet_, &packetQ[thread], packet);
    MOLOCH_COND_SIGNAL(packetQ[thread].lock);
    MOLOCH_UNLOCK(packetQ[thread].lock);
#endif
    return 0;
}
/******************************************************************************/
int moloch_packet_ip4(MolochPacket_t * const packet, const uint8_t *data, int len)
{
    struct ip           *ip4 = (struct ip*)data;
    struct tcphdr       *tcphdr = 0;
    struct udphdr       *udphdr = 0;
#ifdef USE_ONE_SSID
    char                 *sessionId = packet->sessionId;
#else
    char                 sessionId[MOLOCH_SESSIONID_LEN];
#endif

    if (len < (int)sizeof(struct ip))
        return 1;

    int ip_len = ntohs(ip4->ip_len);
    if (len < ip_len)
        return 1;

    int ip_hdr_len = 4 * ip4->ip_hl;
    if (len < ip_hdr_len)
        return 1;

    packet->ipOffset = (uint8_t*)data - packet->pkt;
    packet->payloadOffset = packet->ipOffset + ip_hdr_len;
    packet->payloadLen = ip_len - ip_hdr_len;

    uint16_t ip_off = ntohs(ip4->ip_off);
    uint16_t ip_flags = ip_off & ~IP_OFFMASK;
    ip_off &= IP_OFFMASK;

    if ((ip_flags & IP_MF) || ip_off > 0) {
        moloch_packet_frags4(packet);
        return 0;
    }

    switch (ip4->ip_p) {
    case IPPROTO_TCP:
        if (len < ip_hdr_len + (int)sizeof(struct tcphdr)) {
            return 1;
        }

        tcphdr = (struct tcphdr *)((char*)ip4 + ip_hdr_len);
        moloch_session_id(sessionId, ip4->ip_src.s_addr, tcphdr->th_sport,
                          ip4->ip_dst.s_addr, tcphdr->th_dport);
        packet->ses = SESSION_TCP;
        break;
    case IPPROTO_UDP:
        if (len < ip_hdr_len + (int)sizeof(struct udphdr)) {
            return 1;
        }

        udphdr = (struct udphdr *)((char*)ip4 + ip_hdr_len);

        moloch_session_id(sessionId, ip4->ip_src.s_addr, udphdr->uh_sport,
                          ip4->ip_dst.s_addr, udphdr->uh_dport);
        packet->ses = SESSION_UDP;
        break;
    case IPPROTO_ICMP:
        moloch_session_id(sessionId, ip4->ip_src.s_addr, 0,
                          ip4->ip_dst.s_addr, 0);
        packet->ses = SESSION_ICMP;
        break;
    case IPPROTO_GRE:
        packet->vpnIpOffset = packet->ipOffset; // ipOffset will get reset
        return moloch_packet_gre4(packet, data + ip_hdr_len, len - ip_hdr_len);
    default:
        if (config.logUnknownProtocols)
            LOG("Unknown protocol %d", ip4->ip_p);
        return 1;
    }
    packet->protocol = ip4->ip_p;

#if USE_ONE_SSID
    return moloch_packet_ip(packet);
#else
    return moloch_packet_ip(packet, sessionId);
#endif
}
/******************************************************************************/
int moloch_packet_ip6(MolochPacket_t * const UNUSED(packet), const uint8_t *data, int len)
{
    struct ip6_hdr      *ip6 = (struct ip6_hdr *)data;
    struct tcphdr       *tcphdr = 0;
    struct udphdr       *udphdr = 0;
#ifdef USE_ONE_SSID
    char                 *sessionId = packet->sessionId;
#else
    char                 sessionId[MOLOCH_SESSIONID_LEN];
#endif

    if (len < (int)sizeof(struct ip6_hdr)) {
        return 1;
    }

    int ip_len = ntohs(ip6->ip6_plen);
    if (len < ip_len) {
        return 1;
    }

    int ip_hdr_len = sizeof(struct ip6_hdr);

    packet->ipOffset = (uint8_t*)data - packet->pkt;
    packet->v6 = 1;


    int nxt = ip6->ip6_nxt;
    int done = 0;
    do {
        switch (nxt) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
            nxt = data[ip_hdr_len];
            ip_hdr_len += ((data[ip_hdr_len+1] + 1) << 3);
            break;
        case IPPROTO_FRAGMENT:
            LOG("ERROR - Don't support ip6 fragements yet!");
            return 1;
        case IPPROTO_TCP:
            if (len < ip_hdr_len + (int)sizeof(struct tcphdr)) {
                return 1;
            }

            tcphdr = (struct tcphdr *)(data + ip_hdr_len);

            moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, tcphdr->th_sport,
                               ip6->ip6_dst.s6_addr, tcphdr->th_dport);
            packet->ses = SESSION_TCP;
            done = 1;
            break;
        case IPPROTO_UDP:
            if (len < ip_hdr_len + (int)sizeof(struct udphdr)) {
                return 1;
            }

            udphdr = (struct udphdr *)(data + ip_hdr_len);

            moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, udphdr->uh_sport,
                               ip6->ip6_dst.s6_addr, udphdr->uh_dport);

            packet->ses = SESSION_UDP;
            done = 1;
            break;
        case IPPROTO_ICMP:
            moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, 0,
                               ip6->ip6_dst.s6_addr, 0);
            packet->ses = SESSION_ICMP;
            done = 1;
            break;
        case IPPROTO_ICMPV6:
            moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, 0,
                               ip6->ip6_dst.s6_addr, 0);
            packet->ses = SESSION_ICMP;
            done = 1;
            break;
        default:
            LOG("Unknown protocol %d", ip6->ip6_nxt);
            return 1;
        }
        if (ip_hdr_len > len) {
            LOG ("ERROR - Corrupt packet ip_hdr_len = %d nxt = %d len = %d", ip_hdr_len, nxt, len);
            return 1;
        }
    } while (!done);

    packet->protocol = nxt;
    packet->payloadOffset = packet->ipOffset + ip_hdr_len;
    packet->payloadLen = ip_len - ip_hdr_len + sizeof(struct ip6_hdr);
#ifdef USE_ONE_SSID
    return moloch_packet_ip(packet);
#else
    return moloch_packet_ip(packet, sessionId);
#endif
}
/******************************************************************************/
int moloch_packet_ether(MolochPacket_t * const packet, const uint8_t *data, int len)
{
    if (len < 14) {
        return 1;
    }
    int n = 12;
    while (n+2 < len) {
        int ethertype = data[n] << 8 | data[n+1];
        n += 2;
        switch (ethertype) {
        case 0x0800:
            return moloch_packet_ip4(packet, data+n, len - n);
        case 0x86dd:
            return moloch_packet_ip6(packet, data+n, len - n);
        case 0x8100:
            n += 2;
            break;
        default:
            return 1;
        } // switch
    }
    return 0;
}
/******************************************************************************/
void moloch_packet(MolochPacket_t * const packet)
{
    int rc;

    switch(pcapFileHeader.linktype) {
    case 0: // NULL
        if (packet->pktlen > 4)
            rc = moloch_packet_ip4(packet, packet->pkt+4, packet->pktlen-4);
        else
            rc = 1;
        break;
    case 1: // Ether
        rc = moloch_packet_ether(packet, packet->pkt, packet->pktlen);
        break;
    case 12: // RAW
        rc = moloch_packet_ip4(packet, packet->pkt, packet->pktlen);
        break;
    case 113: // SLL
        rc = moloch_packet_ip4(packet, packet->pkt, packet->pktlen);
        break;
    default:
        LOG("ERROR - Unsupported pcap link type %d", pcapFileHeader.linktype);
        exit (0);
    }
    if (rc) {
        moloch_packet_free(packet);
    }
}
/******************************************************************************/
int moloch_packet_outstanding()
{
    int count = 0;
    int t;

    for (t = 0; t < config.packetThreads; t++) {
#ifdef USE_SPSC_RING
	count += spsc_ring_count(spsc_pktq[t].r);
#else
        count += DLL_COUNT(packet_, &packetQ[t]);
#endif
    }
    return count;
}
/******************************************************************************/
uint32_t moloch_packet_frag_hash(const void *key)
{
    int i;
    uint32_t n = 0;
    for (i = 0; i < 10; i++) {
        n = (n << 5) - n + ((char*)key)[i];
    }
    return n;
}
/******************************************************************************/
int moloch_packet_frag_cmp(const void *keyv, const void *elementv)
{
    MolochFrags_t *element = (MolochFrags_t *)elementv;

    return memcmp(keyv, element->key, 10) == 0;
}
/******************************************************************************/
void moloch_packet_init()
{
    callFilters = config.bpfsNum[MOLOCH_FILTER_DONT_SAVE] || config.bpfsNum[MOLOCH_FILTER_MIN_SAVE];

    pcapFileHeader.magic = 0xa1b2c3d4;
    pcapFileHeader.version_major = 2;
    pcapFileHeader.version_minor = 4;

    pcapFileHeader.thiszone = 0;
    pcapFileHeader.sigfigs = 0;

    mac1Field = moloch_field_define("general", "lotermfield",
        "mac.src", "Src MAC", "mac1-term",
        "Source ethernet mac addresses set for session",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT | MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
        NULL);

    mac2Field = moloch_field_define("general", "lotermfield",
        "mac.dst", "Dst MAC", "mac2-term",
        "Destination ethernet mac addresses set for session",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT | MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
        NULL);

    moloch_field_define("general", "lotermfield",
        "mac", "Src or Dst MAC", "macall",
        "Shorthand for mac.src or mac.dst",
        0,  MOLOCH_FIELD_FLAG_FAKE,
        "regex", "^mac\\\\.(?:(?!\\\\.cnt$).)*$",
        NULL);

    vlanField = moloch_field_define("general", "integer",
        "vlan", "VLan", "vlan",
        "vlan value",
        MOLOCH_FIELD_TYPE_INT_GHASH,  MOLOCH_FIELD_FLAG_COUNT | MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
        NULL);

    greIpField = moloch_field_define("general", "ip",
        "gre.ip", "GRE IP", "greip",
        "GRE ip addresses for session",
        MOLOCH_FIELD_TYPE_IP_GHASH,  MOLOCH_FIELD_FLAG_COUNT | MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
        NULL);

    moloch_field_define("general", "lotermfield",
        "tipv6.src", "IPv6 Src", "tipv61-term",
        "Temporary IPv6 Source",
        0,  MOLOCH_FIELD_FLAG_FAKE,
        "portField", "p1",
        "transform", "ipv6ToHex",
        NULL);

    moloch_field_define("general", "lotermfield",
        "tipv6.dst", "IPv6 Dst", "tipv62-term",
        "Temporary IPv6 Destination",
        0,  MOLOCH_FIELD_FLAG_FAKE,
        "portField", "p2",
        "transform", "ipv6ToHex",
        NULL);

    int t;
#ifdef USE_SPSC_RING
    for(t = 0; t < config.packetThreads; t++) {
        spsc_pktq[t].thread_id = t;
        spsc_pktq[t].r = spsc_ring_create(1048576);
        spsc_pktq[t].dequeue_num = 0;
        spsc_pktq[t].wait_pkt = 0;

        if (spsc_pktq[t].r != NULL) LOG("spsc_ring for thread %d success", t);
    }
#endif
    for (t = 0; t < config.packetThreads; t++) {
        char name[100];
#ifndef USE_SPSC_RING
        DLL_INIT(packet_, &packetQ[t]);
        MOLOCH_LOCK_INIT(packetQ[t].lock);
        MOLOCH_COND_INIT(packetQ[t].lock);
#endif
        snprintf(name, sizeof(name), "moloch-pkt%d", t);
	LOG("tid : %ld", pthread_self());
        g_thread_new(name, &moloch_packet_thread, (gpointer)(long)t);
    }

    DLL_INIT(packet_, &fragsQ);
    MOLOCH_LOCK_INIT(fragsQ.lock);
    MOLOCH_COND_INIT(fragsQ.lock);

    HASH_INIT(fragh_, fragsHash, moloch_packet_frag_hash, moloch_packet_frag_cmp);
    DLL_INIT(fragl_, &fragsList);

    g_thread_new("moloch-frags4", &moloch_packet_frags_thread, NULL);

    moloch_add_can_quit(moloch_packet_outstanding, "packet outstanding");
    moloch_add_can_quit(moloch_packet_frags_outstanding, "packet frags outstanding");
}
/******************************************************************************/
uint64_t moloch_packet_dropped_packets()
{
    MolochReaderStats_t stats;
    if (moloch_reader_stats(&stats)) {
        return 0;
    }
    return stats.dropped - initialDropped;
}
/******************************************************************************/
uint64_t moloch_packet_dropped_frags()
{
    return droppedFrags;
}
/******************************************************************************/
uint64_t moloch_packet_dropped_overload()
{
    uint64_t count = 0;

    int t;

    for (t = 0; t < config.packetThreads; t++) {
        count += overloadDrops[t];
    }
    return count;
}
/******************************************************************************/
void moloch_packet_exit()
{
#ifdef USE_SPSC_RING
    uint64_t total_dequeue = 0;
    int t;
    for(t = 0; t < config.packetThreads; t++) {
        LOG("spsc_pktq %d dequeue %"PRIu64, t, spsc_pktq[t].dequeue_num);
        total_dequeue += spsc_pktq[t].dequeue_num;
    }
    LOG("total dequeue : %"PRIu64, total_dequeue);
#endif
}
