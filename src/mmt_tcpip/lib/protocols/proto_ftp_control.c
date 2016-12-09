/*
 * ftp_control.c
 *
 * Copyright (C) 2016 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

// #include "ftp.h"

#ifdef PROTO_FTP_CONTROL

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ftp_control_add_connection(ipacket_t * ipacket) {

  mmt_internal_add_connection(ipacket, PROTO_FTP_CONTROL, MMT_REAL_PROTOCOL);
}

static int mmt_ftp_control_check_request(const u_int8_t *payload, size_t payload_len) {

  if (mmt_match_strprefix(payload, payload_len, "ABOR")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "ACCT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "ADAT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "ALLO")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "APPE")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "AUTH")) {
    return 1;
  }
  if (mmt_match_strprefix(payload, payload_len, "CCC")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "CDUP")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "CONF")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "CWD")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "DELE")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "ENC")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "EPRT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "EPSV")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "FEAT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "HELP")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "LANG")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "LIST")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "LPRT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "LPSV")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "MDTM")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "MIC")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "MKD")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "MLSD")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "MLST")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "MODE")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "NLST")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "NOOP")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "OPTS")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "PASS")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "PASV")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "PBSZ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "PORT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "PROT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "PWD")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "QUIT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "REIN")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "REST")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "RETR")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "RMD")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "RNFR")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "RNTO")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "SITE")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "SIZE")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "SMNT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "STAT")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "STOR")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "STOU")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "STRU")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "SYST")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "TYPE")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "USER")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "XCUP")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "XMKD")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "XPWD")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "XRCP")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "XRMD")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "XRSQ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "XSEM")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "XSEN")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "HOST")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "abor")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "acct")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "adat")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "allo")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "appe")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "auth")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "ccc")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "cdup")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "conf")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "cwd")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "dele")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "enc")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "eprt")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "epsv")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "feat")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "help")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "lang")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "list")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "lprt")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "lpsv")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "mdtm")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "mic")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "mkd")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "mlsd")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "mlst")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "mode")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "nlst")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "noop")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "opts")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "pass")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "pasv")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "pbsz")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "port")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "prot")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "pwd")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "quit")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "rein")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "rest")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "retr")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "rmd")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "rnfr")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "rnto")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "site")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "size")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "smnt")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "stat")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "stor")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "stou")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "stru")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "syst")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "type")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "user")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "xcup")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "xmkd")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "xpwd")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "xrcp")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "xrmd")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "xrsq")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "xsem")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "xsen")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "host")) {
    return 1;
  }

  return 0;
}

static int mmt_ftp_control_check_response(const u_int8_t *payload, size_t payload_len) {

  if (mmt_match_strprefix(payload, payload_len, "110-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "120-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "125-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "150-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "202-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "211-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "212-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "213-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "214-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "215-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "220-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "221-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "225-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "226-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "227-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "228-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "229-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "230-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "231-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "232-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "250-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "257-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "331-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "332-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "350-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "421-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "425-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "426-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "430-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "434-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "450-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "451-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "452-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "501-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "502-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "503-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "504-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "530-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "532-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "550-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "551-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "552-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "553-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "631-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "632-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "633-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10054-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10060-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10061-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10066-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10068-")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "110 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "120 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "125 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "150 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "202 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "211 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "212 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "213 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "214 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "215 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "220 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "221 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "225 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "226 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "227 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "228 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "229 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "230 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "231 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "232 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "250 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "257 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "331 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "332 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "350 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "421 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "425 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "426 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "430 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "434 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "450 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "451 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "452 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "501 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "502 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "503 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "504 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "530 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "532 ")) {
    return 1;
  }
  if (mmt_match_strprefix(payload, payload_len, "550 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "551 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "552 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "553 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "631 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "632 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "633 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10054 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10060 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10061 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10066 ")) {
    return 1;
  }

  if (mmt_match_strprefix(payload, payload_len, "10068 ")) {
    return 1;
  }

  return 0;
}

int mmt_check_ftp_control(ipacket_t * ipacket, unsigned index) {

  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;
  if (packet->detected_protocol_stack[0] != PROTO_FTP_CONTROL) {
    if (packet->tcp_retransmission == 0) {
      u_int32_t payload_len = packet->payload_packet_len;

      /* Check connection over TCP */
      if (packet->tcp) {

        /* Exclude SMTP, which uses similar commands. */
        if (packet->tcp->dest == htons(25) || packet->tcp->source == htons(25)) {
          MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "Exclude FTP_CONTROL.\n");
          MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP_CONTROL);
          return 0;
        }

        /* Break after 20 packets. */
        if (flow->packet_counter > 20) {
          MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "Exclude FTP_CONTROL.\n");
          MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP_CONTROL);
          return 0;
        }

        /* Check if we so far detected the protocol in the request or not. */
        if (flow->ftp_control_stage == 0) {
          MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "FTP_CONTROL stage 0: \n");

          if ((payload_len > 0) && mmt_ftp_control_check_request(packet->payload, payload_len)) {
            MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "Possible FTP_CONTROL request detected, we will look further for the response...\n");

            /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
            flow->ftp_control_stage = packet->packet_direction + 1;
          }
          if ((payload_len > 0) && mmt_ftp_control_check_response(packet->payload, payload_len)) {
            MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "Found FTP_CONTROL.\n");
            mmt_int_ftp_control_add_connection(ipacket);
            return 1;
          }
        } else {
          MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "FTP_CONTROL stage %u: \n", flow->ftp_control_stage);

          /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
          if ((flow->ftp_control_stage - packet->packet_direction) == 1) {
            return 4;
          }

          /* This is a packet in another direction. Check if we find the proper response. */
          if ((payload_len > 0) && mmt_ftp_control_check_response(packet->payload, payload_len)) {
            MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "Found FTP_CONTROL.\n");
            mmt_int_ftp_control_add_connection(ipacket);
            return 1;
          } else {
            MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "The reply did not seem to belong to FTP_CONTROL, resetting the stage to 0...\n");
            flow->ftp_control_stage = 0;
            return 0;
          }
        }
      }
    }
  }
  return 4;
}

// void ndpi_search_ftp_control(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
//   struct ndpi_packet_struct *packet = &flow->packet;

//   MMT_LOG(PROTO_FTP_CONTROL, MMT_LOG_DEBUG, "FTP_CONTROL detection...\n");

//   /* skip marked packets */
//   if (packet->detected_protocol_stack[0] != PROTO_FTP_CONTROL) {
//     if (packet->tcp_retransmission == 0) {
//       ndpi_check_ftp_control(ndpi_struct, flow);
//     }
//   }
// }


// void init_ftp_control_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
// {
//   ndpi_set_bitmask_protocol_detection("FTP_CONTROL", ndpi_struct, detection_bitmask, *id,
//              PROTO_FTP_CONTROL,
//              ndpi_search_ftp_control,
//              NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION,
//              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//              ADD_TO_DETECTION_BITMASK);

//   *id += 1;
// }

void mmt_init_classify_me_ftp_control() {
  selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION;
  MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
  MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FTP_CONTROL);
  MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FTP_CONTROL);
}

int init_proto_ftp_control_struct() {

  // debug("QUIC: init_proto_FTP_CONTROL_struct");

  protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FTP_CONTROL, PROTO_FTP_CONTROL_ALIAS);
  if (protocol_struct != NULL) {
    // int i = 0;
    // for (; i < NDN_ATTRIBUTES_NB; i++) {
    //     register_attribute_with_protocol(protocol_struct, &ndn_attributes_metadata[i]);
    // }
    // register_pre_post_classification_functions(protocol_struct, NULL, NULL);
    // register_proto_context_init_cleanup_function(protocol_struct, setup_ndn_context, cleanup_ndn_context, NULL);
    // register_session_data_analysis_function(protocol_struct, ndn_session_data_analysis);
    mmt_init_classify_me_ftp_control();

    return register_protocol(protocol_struct, PROTO_FTP_CONTROL);
  } else {
    return 0;
  }
}

#endif