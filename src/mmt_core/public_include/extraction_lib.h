/*
 * File:   protocol_extraction_functions.h
 * Author: montimage
 *
 * Created on 8 mars 2011, 16:04
 */

#ifndef PROTOCOL_EXTRACTION_FUNCTIONS_H
#define PROTOCOL_EXTRACTION_FUNCTIONS_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdlib.h>
#include <string.h>
#include "data_defs.h"
#include "mmt_core.h"
#include <stdint.h>

/**
 * Silent extraction function, does nothing.
 * @param packet pointer to the packet structure data
 * @param proto_index index of the protocol in the protocols hierarchy
 * @param extracted_data pointer to attribute structure where the extracted data will be stored
 * @return Will always succeed, returns a positive value.
 */
MMTAPI int MMTCALL silent_extraction(const ipacket_t *packet, unsigned proto_index, attribute_t *extracted_data);

/* ************************************* */
/* **** General Extraction Functions *** */

/**
 * Generic extraction function. It will copy into extracted_data, attr_data_len bytes starting from an offset
 * corresponding to the sum of the proto_offset and the attribute offset from the data part of the packet structure.
 * @param packet pointer to the packet structure data
 * @param proto_index index of the protocol in the protocols hierarchy
 * @param extracted_data pointer to the attribute struct where the extracted data will be stored
 * @return Positive value if the extraction succeeded, a negative value otherwise.
 */

MMTAPI int MMTCALL general_byte_to_byte_extraction(const ipacket_t *packet, unsigned proto_index,
												   attribute_t *extracted_data);

MMTAPI int MMTCALL general_short_extraction_with_ordering_change(const ipacket_t *packet, unsigned proto_index,
																 attribute_t *extracted_data);

MMTAPI int MMTCALL general_int_extraction_with_ordering_change(const ipacket_t *packet, unsigned proto_index,
															   attribute_t *extracted_data);

MMTAPI int MMTCALL general_char_extraction(const ipacket_t *packet, unsigned proto_index, attribute_t *extracted_data);

MMTAPI int MMTCALL general_short_extraction(const ipacket_t *packet, unsigned proto_index, attribute_t *extracted_data);

MMTAPI int MMTCALL general_int_extraction(const ipacket_t *packet, unsigned proto_index, attribute_t *extracted_data);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_EXTRACTION_FUNCTIONS_H */
