#ifndef MMT_SAFE_ACCESS_H
#define MMT_SAFE_ACCESS_H

#include <stdint.h>
#include <stdbool.h>
#include "data_defs.h"

/**
 * Validate that offset + len is within packet bounds
 * @param pkt Packet to check
 * @param offset Starting offset
 * @param len Length to access
 * @return true if access is safe, false otherwise
 */
static inline bool mmt_validate_offset(const ipacket_t *pkt, uint32_t offset, uint32_t len)
{
	if (pkt == NULL || pkt->p_hdr == NULL) {
		return false;
	}
	// Check for integer overflow
	if (offset + len < offset) {
		return false;
	}
	// Check bounds
	return (offset + len <= pkt->p_hdr->caplen);
}

/**
 * Get a safe pointer to packet data
 * @param pkt Packet
 * @param offset Starting offset
 * @param len Length required
 * @return Pointer to data if safe, NULL otherwise
 */
static inline const uint8_t *mmt_safe_packet_ptr(const ipacket_t *pkt, uint32_t offset, uint32_t len)
{
	if (!mmt_validate_offset(pkt, offset, len)) {
		return NULL;
	}
	return &pkt->data[offset];
}

/**
 * Safe cast to structure type
 * Usage: const struct foo *f = MMT_SAFE_CAST(pkt, offset, struct foo);
 */
#define MMT_SAFE_CAST(pkt, offset, type) \
	((const type *)(mmt_validate_offset(pkt, offset, sizeof(type)) ? &pkt->data[offset] : NULL))

#endif /* MMT_SAFE_ACCESS_H */
