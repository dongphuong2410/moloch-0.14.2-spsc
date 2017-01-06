/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <ctype.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "process.h"
#include "readfp.h"
#include "p0f.h"
#include "tcp.h"
#include "handler.h"

#include "fp_mtu.h"


/* Register a new MTU signature. */

void mtu_register_sig(p0fhdlr *hdlr, u8* name, u8* val, u32 line_no) {

  u8* nxt = val;
  s32 mtu;
  u32 bucket;

  while (isdigit(*nxt)) nxt++;

  if (nxt == val || *nxt) FATAL("Malformed MTU value in line %u.", line_no);

  mtu = atol((char*)val);

  if (mtu <= 0 || mtu > 65535) FATAL("Malformed MTU value in line %u.", line_no);

  bucket = mtu % SIG_BUCKETS;

  hdlr->mtusigs[bucket] = DFL_ck_realloc(hdlr->mtusigs[bucket], (hdlr->mtu_sig_cnt[bucket] + 1) *
                                sizeof(struct mtu_sig_record));

  hdlr->mtusigs[bucket][hdlr->mtu_sig_cnt[bucket]].mtu = mtu;
  hdlr->mtusigs[bucket][hdlr->mtu_sig_cnt[bucket]].name = name;

  hdlr->mtu_sig_cnt[bucket]++;

}



void fingerprint_mtu(p0fhdlr *hdlr, u8 to_srv, struct packet_data* pk, struct packet_flow* f) {

  u32 bucket, i, mtu;

  if (!pk->mss || f->sendsyn) return;

  if (pk->ip_ver == IP_VER4) mtu = pk->mss + MIN_TCP4;
  else mtu = pk->mss + MIN_TCP6;

  bucket = (mtu) % SIG_BUCKETS;

  for (i = 0; i < hdlr->mtu_sig_cnt[bucket]; i++)
    if (hdlr->mtusigs[bucket][i].mtu == mtu) break;

  if (i != hdlr->mtu_sig_cnt[bucket]){
    if (to_srv) f->client->link_type = hdlr->mtusigs[bucket][i].name;
    else f->server->link_type = hdlr->mtusigs[bucket][i].name;
  }
}
