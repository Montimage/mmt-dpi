#include "extraction_lib.h"
#include "mmt_core.h"

int silent_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {
    return 0;
}

int general_byte_to_byte_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0 || attr_data_len <= 0) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + (size_t)attr_data_len > packet->p_hdr->caplen) return 0;

    memcpy((u_char *) extracted_data->data, (char *) & packet->data[proto_offset + attribute_offset], attr_data_len);
    return 1;
}

int general_short_extraction_with_ordering_change(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint16_t) > packet->p_hdr->caplen) return 0;

    // Issue #193: memcpy, not an aligned-type dereference — attribute offsets
    // are not guaranteed aligned (odd positions exist), which is UB and trips
    // UBSan.
    uint16_t v16;
    memcpy(&v16, & packet->data[proto_offset + attribute_offset], sizeof(v16));
    v16 = ntohs(v16);
    memcpy(extracted_data->data, &v16, sizeof(v16));
    return 1;
}

int general_int_extraction_with_ordering_change(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint32_t) > packet->p_hdr->caplen) return 0;

    // Issue #193: memcpy — see general_short_extraction_with_ordering_change.
    uint32_t v32;
    memcpy(&v32, & packet->data[proto_offset + attribute_offset], sizeof(v32));
    v32 = ntohl(v32);
    memcpy(extracted_data->data, &v32, sizeof(v32));
    return 1;
}

int general_char_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint8_t) > packet->p_hdr->caplen) return 0;

    *((unsigned char *) extracted_data->data) = *((unsigned char *) & packet->data[proto_offset + attribute_offset]);
    return 1;
}

int general_short_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint16_t) > packet->p_hdr->caplen) return 0;

    // Issue #193: memcpy — see general_short_extraction_with_ordering_change.
    uint16_t v16;
    memcpy(&v16, & packet->data[proto_offset + attribute_offset], sizeof(v16));
    memcpy(extracted_data->data, &v16, sizeof(v16));
    return 1;
}

int general_int_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = extracted_data->data_len;
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + sizeof(uint32_t) > packet->p_hdr->caplen) return 0;

    // Issue #193: memcpy — see general_short_extraction_with_ordering_change.
    uint32_t v32;
    memcpy(&v32, & packet->data[proto_offset + attribute_offset], sizeof(v32));
    memcpy(extracted_data->data, &v32, sizeof(v32));
    return 1;
}

