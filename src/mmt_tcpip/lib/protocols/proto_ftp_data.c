/*
 * ftp_data.c
 *
 * Copyright (C) 2016 - ntop.org
 * 
 * The signature is based on the Libprotoident library.
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

#ifdef PROTO_FTP_DATA

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ftp_data_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_FTP_DATA, MMT_REAL_PROTOCOL);
}

static int mmt_match_ftp_data_port(ipacket_t * ipacket) {
  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

  /* Check connection over TCP */
  if(packet->tcp) {
    if(packet->tcp->dest == htons(20) || packet->tcp->source == htons(20)) {
      return 1;
    }
  }
  return 0;
}

static int mmt_match_ftp_data_directory(ipacket_t * ipacket) {
  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  u_int32_t payload_len = packet->payload_packet_len;

  if((payload_len >= 4)
      && ((packet->payload[0] == '-') || (packet->payload[0] == 'd'))
      && ((packet->payload[1] == '-') || (packet->payload[1] == 'r'))
      && ((packet->payload[2] == '-') || (packet->payload[2] == 'w'))
      && ((packet->payload[3] == '-') || (packet->payload[3] == 'x'))) {

    return 1;
  }

  return 0;
}

static int mmt_match_file_header(ipacket_t * ipacket) {
  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  u_int32_t payload_len = packet->payload_packet_len;

  /* A FTP packet is pretty long so 256 is a bit consrvative but it should be OK */
  if(packet->payload_packet_len < 256)
    return 0;

  /* RIFF is a meta-format for storing AVI and WAV files */
  if(mmt_match_strprefix(packet->payload, payload_len, "RIFF"))
    return 1;

  /* MZ is a .exe file */
  if((packet->payload[0] == 'M') && (packet->payload[1] == 'Z') && (packet->payload[3] == 0x00))
    return 1;

  /* Ogg files */
  if(mmt_match_strprefix(packet->payload, payload_len, "OggS"))
    return 1;

  /* ZIP files */
  if((packet->payload[0] == 'P') && (packet->payload[1] == 'K') && (packet->payload[2] == 0x03) && (packet->payload[3] == 0x04))
    return 1;

  /* MPEG files */
  if((packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x01) && (packet->payload[3] == 0xba))
    return 1;

  /* RAR files */
  if(mmt_match_strprefix(packet->payload, payload_len, "Rar!"))
    return 1;

  /* EBML */
  if((packet->payload[0] == 0x1a) && (packet->payload[1] == 0x45) && (packet->payload[2] == 0xdf) && (packet->payload[3] == 0xa3))
    return 1;

  /* JPG */
  if((packet->payload[0] == 0xff) && (packet->payload[1] ==0xd8))
    return 1;

  /* GIF */
  if(mmt_match_strprefix(packet->payload, payload_len, "GIF8"))
    return 1;

  /* PHP scripts */
  if((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x3f) && (packet->payload[2] == 0x70) && (packet->payload[3] == 0x68))
    return 1;

  /* Unix scripts */
  if((packet->payload[0] == 0x23) && (packet->payload[1] == 0x21) && (packet->payload[2] == 0x2f) && (packet->payload[3] == 0x62))
    return 1;

  /* PDFs */
  if(mmt_match_strprefix(packet->payload, payload_len, "%PDF"))
    return 1;

  /* PNG */
  if((packet->payload[0] == 0x89) && (packet->payload[1] == 'P') && (packet->payload[2] == 'N') && (packet->payload[3] == 'G'))
    return 1;

  /* HTML */
  if(mmt_match_strprefix(packet->payload, payload_len, "<htm"))
    return 1;
  if((packet->payload[0] == 0x0a) && (packet->payload[1] == '<') && (packet->payload[2] == '!') && (packet->payload[3] == 'D'))
    return 1;

  /* 7zip */
  if((packet->payload[0] == 0x37) && (packet->payload[1] == 0x7a) && (packet->payload[2] == 0xbc) && (packet->payload[3] == 0xaf))
    return 1;

  /* gzip */
  if((packet->payload[0] == 0x1f) && (packet->payload[1] == 0x8b) && (packet->payload[2] == 0x08))
    return 1;

  /* XML */
  if(mmt_match_strprefix(packet->payload, payload_len, "<!DO"))
    return 1;

  /* FLAC */
  if(mmt_match_strprefix(packet->payload, payload_len, "fLaC"))
    return 1;

  /* MP3 */
  if((packet->payload[0] == 'I') && (packet->payload[1] == 'D') && (packet->payload[2] == '3') && (packet->payload[3] == 0x04 || packet->payload[3] == 0x03 ))
    return 1;
  if(mmt_match_strprefix(packet->payload, payload_len, "\xff\xfb\x90\xc0"))
    return 1;

  /* RPM */
  if((packet->payload[0] == 0xed) && (packet->payload[1] == 0xab) && (packet->payload[2] == 0xee) && (packet->payload[3] == 0xdb))
    return 1;

  /* Wz Patch */
  if(mmt_match_strprefix(packet->payload, payload_len, "WzPa"))
    return 1;

  /* Flash Video */
  if((packet->payload[0] == 'F') && (packet->payload[1] == 'L') && (packet->payload[2] == 'V') && (packet->payload[3] == 0x01))
    return 1;

  /* .BKF (Microsoft Tape Format) */
  if(mmt_match_strprefix(packet->payload, payload_len, "TAPE"))
    return 1;

  /* MS Office Doc file - this is unpleasantly geeky */
  if((packet->payload[0] == 0xd0) && (packet->payload[1] == 0xcf) && (packet->payload[2] == 0x11) && (packet->payload[3] == 0xe0))
    return 1;

  /* ASP */
  if((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x25) && (packet->payload[2] == 0x40) && (packet->payload[3] == 0x20))
    return 1;

  /* WMS file */
  if((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x21) && (packet->payload[2] == 0x2d) && (packet->payload[3] == 0x2d))
    return 1;

  /* ar archive, typically .deb files */
  if(mmt_match_strprefix(packet->payload, payload_len, "!<ar"))
    return 1;

  /* Raw XML (skip jabber-like traffic as this is not FTP but unencrypted jabber) */
  if((mmt_match_strprefix(packet->payload, payload_len, "<?xm"))
     && (mmt_strnstr((const char *)packet->payload, "jabber", packet->payload_packet_len) == NULL))
    return 1;

  if(mmt_match_strprefix(packet->payload, payload_len, "<iq "))
    return 1;

  /* SPF */
  if(mmt_match_strprefix(packet->payload, payload_len, "SPFI"))
    return 1;

  /* ABIF - Applied Biosystems */
  if(mmt_match_strprefix(packet->payload, payload_len, "ABIF"))
    return 1;

  /* bzip2 - other digits are also possible instead of 9 */
  if((packet->payload[0] == 'B') && (packet->payload[1] == 'Z') && (packet->payload[2] == 'h') && (packet->payload[3] == '9'))
    return 1;

  /* Some other types of files */

  if((packet->payload[0] == '<') && (packet->payload[1] == 'c') && (packet->payload[2] == 'f'))
    return 1;
  if((packet->payload[0] == '<') && (packet->payload[1] == 'C') && (packet->payload[2] == 'F'))
    return 1;
  if(mmt_match_strprefix(packet->payload, payload_len, ".tem"))
    return 1;
  if(mmt_match_strprefix(packet->payload, payload_len, ".ite"))
    return 1;
  if(mmt_match_strprefix(packet->payload, payload_len, ".lef"))
    return 1;

  if(packet->payload[0]==0x00 && packet->payload[1]==0x00 && packet->payload[2]==0x00 && packet->payload[3]==0x18 &&mmt_match_strprefix(packet->payload+4, payload_len, "ftypmp4"))
    return 1;  

  return 0;
}

int mmt_check_ftp_data(ipacket_t * ipacket, unsigned index) {
  debug("[PROTO_FTP_DATA] mmt_check_ftp_data: %lu",ipacket->packet_id);
  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;
  if(flow->packet_counter > 20) {
    MMT_LOG(PROTO_FTP_DATA, MMT_LOG_DEBUG, "Exclude FTP_DATA.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP_DATA);
    return 0;
  }

  MMT_LOG(PROTO_FTP_DATA, MMT_LOG_DEBUG, "FTP_DATA detection...\n");
  if((packet->payload_packet_len > 0)
     && (mmt_match_file_header(ipacket)
   || mmt_match_ftp_data_directory(ipacket) 
   || mmt_match_ftp_data_port(ipacket)
   )
     ) {
    MMT_LOG(PROTO_FTP_DATA, MMT_LOG_DEBUG, "Possible FTP_DATA request detected...\n");
    mmt_int_ftp_data_add_connection(ipacket);
    return 1;
  } else
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP_DATA);   
    return 0;
}

// void ndpi_search_ftp_data(ipacket_t * ipacket) {
	
//   /* Break after 20 packets. */
//   if(flow->packet_counter > 20) {
//     MMT_LOG(PROTO_FTP_DATA, MMT_LOG_DEBUG, "Exclude FTP_DATA.\n");
//     MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP_DATA);
//     return;
//   }

//   MMT_LOG(PROTO_FTP_DATA, MMT_LOG_DEBUG, "FTP_DATA detection...\n");
//   mmt_check_ftp_data(ndpi_struct, flow);
// }


// void init_ftp_data_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
// {
//   ndpi_set_bitmask_protocol_detection("FTP_DATA", ndpi_struct, detection_bitmask, *id,
// 				      PROTO_FTP_DATA,
// 				      ndpi_search_ftp_data,
// 				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
// 				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
// 				      ADD_TO_DETECTION_BITMASK);

//   *id += 1;
// }


void mmt_init_classify_me_ftp_data() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FTP_DATA);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FTP_DATA);
}

int init_proto_ftp_data_struct() {
    
    // debug("QUIC: init_proto_FTP_DATA_struct");

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FTP_DATA, PROTO_FTP_DATA_ALIAS);
    if (protocol_struct != NULL) {
        // int i = 0;
        // for (; i < NDN_ATTRIBUTES_NB; i++) {
        //     register_attribute_with_protocol(protocol_struct, &ndn_attributes_metadata[i]);
        // }
        // register_pre_post_classification_functions(protocol_struct, NULL, NULL);
        // register_proto_context_init_cleanup_function(protocol_struct, setup_ndn_context, cleanup_ndn_context, NULL);
        // register_session_data_analysis_function(protocol_struct, ndn_session_data_analysis);
        mmt_init_classify_me_ftp_data();

        return register_protocol(protocol_struct, PROTO_FTP_DATA);
    } else {
        return 0;
    }
}

#endif
