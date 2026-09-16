#include <string.h> // memcpy()

#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "packet_processing.h" /* mmt_have_bytes() — issue #202 caplen prologues */
#include "../mmt_common_internal_include.h"

#include "gre.h"
#define GRE_P_PPP  0x880b
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
/* Issue #201 (F-BUG-035): every gre_hdr field read below must first pass this
 * captured-length check — the 4-byte base header (flags + protocol) has to be
 * inside the capture. */
static inline int gre_base_captured(const ipacket_t * packet, int proto_offset) {
    return proto_offset >= 0
        && (uint64_t) proto_offset + sizeof(struct gre_hdr) - 1 <= packet->p_hdr->caplen;
}

/* Same, for an optional 32-bit field `index`-th positions after the base
 * header (index = number of preceding optional fields). */
static inline int gre_field_captured(const ipacket_t * packet, int proto_offset, int index) {
    return gre_base_captured(packet, proto_offset)
        && (uint64_t) proto_offset + 4 + (uint64_t) index * 4 + 4 <= packet->p_hdr->caplen;
}

int gre_c_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — every packet byte this
     * callback dereferences must lie inside the captured data. The flag
     * bits all live in the first uint16_t of the GRE header. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint16_t))) return 0;
    struct gre_hdr * grehdr = (struct gre_hdr *) & packet->data[proto_offset];

    *((unsigned short *) extracted_data->data) = grehdr->csum;
    return 1;
}

int gre_k_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see gre_c_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint16_t))) return 0;
    struct gre_hdr * grehdr = (struct gre_hdr *) & packet->data[proto_offset];

    *((unsigned short *) extracted_data->data) = grehdr->key;
    return 1;
}

int gre_s_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see gre_c_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint16_t))) return 0;
    struct gre_hdr * grehdr = (struct gre_hdr *) & packet->data[proto_offset];

    *((unsigned short *) extracted_data->data) = grehdr->seq;
    return 1;
}

int gre_version_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see gre_c_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint16_t))) return 0;
    struct gre_hdr * grehdr = (struct gre_hdr *) & packet->data[proto_offset];

    *((unsigned short *) extracted_data->data) = grehdr->version;
    return 1;
}

int gre_csum_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see gre_c_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    /* The checksum is the first optional 32-bit field — index 0. */
    if (!gre_field_captured(packet, proto_offset, 0))
        return 0;
    struct gre_hdr * grehdr = (struct gre_hdr *) & packet->data[proto_offset];

    if (grehdr->csum) {
        /* The optional checksum field sits at offset 4 and is 4 bytes wide
         * (this code reads its first byte via the 'data' member). */
        if (!mmt_have_bytes(packet, (size_t) proto_offset + 4, sizeof(uint32_t))) return 0;
        *((unsigned short *) extracted_data->data) = ntohs(grehdr->data);
        return 1;
    }
    return 0;
}

int gre_key_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see gre_c_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint16_t))) return 0;
    struct gre_hdr * grehdr = (struct gre_hdr *) & packet->data[proto_offset];

    int nb_lignes = 0;
    if (grehdr->key) {
        if (grehdr->csum) {
            nb_lignes++;
        }
        /* The key field is a 4-byte optional word at offset 4 + nb_lignes*4. */
        if (!mmt_have_bytes(packet, (size_t) proto_offset + 4 + (size_t) nb_lignes * 4, sizeof(uint32_t))) return 0;
        /* Issue #202: the capture buffer is byte-aligned — a strict u32 load
         * at an odd offset is a misaligned access (UBSan aborts). memcpy is
         * alignment-safe; mirrors the issue #59 fixes. */
        uint32_t key_word;
        memcpy(&key_word, &((uint8_t *) & grehdr->data)[nb_lignes * 4], sizeof(key_word));
        *((uint32_t *) extracted_data->data) = ntohl(key_word);
        return 1;
    }
    return 0;
}

int gre_seqnb_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see gre_c_flag_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint16_t))) return 0;
    struct gre_hdr * grehdr = (struct gre_hdr *) & packet->data[proto_offset];

    int nb_lignes = 0;
    if (grehdr->seq) {
        if (grehdr->csum) {
            nb_lignes++;
        }
        if (grehdr->key) {
            nb_lignes++;
        }
        /* The seq field is a 4-byte optional word at offset 4 + nb_lignes*4. */
        if (!mmt_have_bytes(packet, (size_t) proto_offset + 4 + (size_t) nb_lignes * 4, sizeof(uint32_t))) return 0;
        /* Issue #202: memcpy — alignment-safe, see gre_key_extraction. */
        uint32_t seq_word;
        memcpy(&seq_word, &((uint8_t *) & grehdr->data)[nb_lignes * 4], sizeof(seq_word));
        *((uint32_t *) extracted_data->data) = ntohl(seq_word);
        return 1;
    }
    return 0;
}

int gre_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;

    int offset = get_packet_offset_at_index(ipacket, index);

    /* Issue #201 (F-BUG-035): the base GRE header (flags + protocol) must be
     * captured before any flag bit is read. */
    if (!gre_base_captured(ipacket, offset))
        return 0;

    struct gre_hdr * grehdr = (struct gre_hdr *) & ipacket->data[offset];

    int nb_lignes = 0;
    if (grehdr->seq) {
        nb_lignes++;
    }
    if (grehdr->csum) {
        nb_lignes++;
    }
    if (grehdr->key) {
        nb_lignes++;
    }

    /* Issue #201 (F-BUG-035): all optional fields must be captured before the
     * encapsulated protocol is classified at 4 + nb_lignes*4. */
    if (nb_lignes > 0 && !gre_field_captured(ipacket, offset, nb_lignes - 1))
        return 0;


    switch (ntohs(grehdr->protocol)) // Encapsulated protocol identifier
    {
            /* IPv4 */
        case ETH_P_IP:
            retval.proto_id = PROTO_IP;
            retval.offset = 4 + nb_lignes * 4;
            //ipacket->session->tcp_udp_index = index + 1;
            retval.status = Classified;
            break;
            /* IPv6 */
        case ETH_P_IPV6:
            retval.proto_id = PROTO_IPV6;
            retval.offset = 4 + nb_lignes * 4;
            //ipacket->session->tcp_udp_index = index + 1;
            retval.status = Classified;
            break;
        // IEEE1588           
        case GRE_P_PPP:
            retval.proto_id = PROTO_PPP;
            retval.offset = 4 + nb_lignes * 4;
            retval.status = Classified;
            break; 
        default:
            retval.proto_id = PROTO_UNKNOWN;
            retval.offset = 4 + nb_lignes * 4;
            retval.status = Classified;
            break;
    }
    
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

static attribute_metadata_t gre_attributes_metadata[GRE_ATTRIBUTES_NB] = {
    {GRE_FLAGS, GRE_FLAGS_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, general_byte_to_byte_extraction},
    {GRE_C_FLAG, GRE_C_FLAG_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, gre_c_flag_extraction},
    {GRE_K_FLAG, GRE_K_FLAG_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, gre_k_flag_extraction},
    {GRE_S_FLAG, GRE_S_FLAG_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, gre_s_flag_extraction},
    {GRE_VERSION, GRE_VERSION_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, gre_version_extraction},
    {GRE_PROTOCOL, GRE_PROTOCOL_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_byte_to_byte_extraction},

    {GRE_CHECKSUM, GRE_CHECKSUM_ALIAS, MMT_U16_DATA, sizeof (short), 4, SCOPE_PACKET, gre_csum_extraction},
    {GRE_KEY, GRE_KEY_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, gre_key_extraction},
    {GRE_SEQ_NB, GRE_SEQ_NB_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, gre_seqnb_extraction},

    //TODO(#331): support for the following attributes: we need a hash map that links the GRE keys and the sequence numbers
    {GRE_OUT_SEQENCE, GRE_OUT_SEQENCE_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, silent_extraction},
    {GRE_IN_SEQENCE, GRE_IN_SEQENCE_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, silent_extraction},
    {GRE_SEQENCE_GAP, GRE_SEQENCE_GAP_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, silent_extraction},
    {GRE_LOSS, GRE_LOSS_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, silent_extraction},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_gre_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_GRE, PROTO_GRE_ALIAS);

    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < GRE_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &gre_attributes_metadata[i]);
        }

        register_classification_function(protocol_struct, gre_classify_next_proto);
        
        return register_protocol(protocol_struct, PROTO_GRE);
    } else {
        return 0;
    }
}


