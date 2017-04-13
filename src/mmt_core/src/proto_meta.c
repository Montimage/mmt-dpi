#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "packet_processing.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
int utime_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    //int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t *protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    memcpy(extracted_data->data, & packet->p_hdr->ts, sizeof (struct timeval));
    return 1;
}

int uargs_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    extracted_data->data = packet->p_hdr->user_args;
    return 1;
}

int probe_id_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    *((unsigned int *) extracted_data->data) = packet->p_hdr->probe_id;
    return 1;
}

int source_id_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    *((unsigned int *) extracted_data->data) = packet->p_hdr->source_id;
    return 1;
}

int packet_direction_extraction (const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session == NULL) {
        //Packet does not belong to a session, the direction is by default from initiator to server
        *((unsigned int *) extracted_data->data) = FROM_INITIATOR;
        return 1;
    }else {
        //Packet belongs to a session, the direction is that of the last packet of the session
        *((unsigned int *) extracted_data->data) = packet->session->last_packet_direction;
        return 1;
    }
}

int proto_hierarchy_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    //int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t *protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    memcpy(extracted_data->data, packet->proto_hierarchy, sizeof (proto_hierarchy_t));
    return 1;
}

int plen_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    //int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t *protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    *((unsigned int *) extracted_data->data) = packet->p_hdr->len;
    return 1;
}

int session_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    //int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t *protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);
    if (packet->session == NULL) {
        extracted_data->data = NULL;
        return 0;
    }
    if (packet->session->packet_count == 1) {
        extracted_data->data = packet->session;
        return 1;
    }
    return 0;
}

int classified_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if (packet->session == NULL) {
        return 0;
    } else if (packet->session->status == Classified) {
        *((char *) extracted_data->data) = packet->session->status;
        return 1;
    }
    return 0;
}

//This function is not used yet!

void meta_session_data_init(ipacket_t * ipacket, unsigned index) {
}

void meta_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    //struct base_session_data_struct * base_session_data = ipacket->session->session_data[index];
    //int offset = get_packet_offset_at_index(ipacket, index);
}

static attribute_metadata_t meta_attributes_metadata[META_ATTRIBUTES_NB] = {
    {META_PACKET_DIRECTION, META_PACKET_DIRECTION_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, packet_direction_extraction},
    {META_UARGS, META_UARGS_ALIAS, MMT_DATA_POINTER, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_PACKET, uargs_extraction},
    {META_UTIME, META_UTIME_ALIAS, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_PACKET, utime_extraction},
    {META_P_LEN, META_P_LEN_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, plen_extraction},
    {META_PROTO_H, META_PROTO_H_ALIAS, MMT_DATA_PATH, sizeof (proto_hierarchy_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_hierarchy_extraction},
    {META_SESSION, META_SESSION_ALIAS, MMT_DATA_POINTER, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, session_extraction},
    {META_CLASSIFIED, META_CLASSIFIED_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_SESSION, classified_extraction},
    {META_PROBE_ID, META_PROBE_ID_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_SESSION, probe_id_extraction},
    {META_SOURCE_ID, META_SOURCE_ID_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_SESSION, source_id_extraction},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_meta_struct() {
    protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_META, PROTO_META_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < META_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &meta_attributes_metadata[i]);
        }

        //TODO: these initializations need to be done
        register_session_data_initialization_function(protocol_struct, NULL);
        register_session_data_analysis_function(protocol_struct, NULL);
        register_session_data_cleanup_function(protocol_struct, NULL);

        register_classification_function(protocol_struct, base_classify_next_proto);

        return register_protocol(protocol_struct, PROTO_META);
    } else {
        return 0;
    }
}

int init_proto_unknown_struct() {
    protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_UNKNOWN, PROTO_UNKNOWN_ALIAS);

    if (protocol_struct != NULL) {

        return register_protocol(protocol_struct, PROTO_UNKNOWN);
    } else {
        return 0;
    }
}

