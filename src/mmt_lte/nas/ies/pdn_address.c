#include "../util/decoder.h"
#include "pdn_address.h"

int nas_decode_pdn_address(nas_pdn_address_t *addr, uint8_t iei, const uint8_t *buffer, uint32_t len)
{
  int decoded = 0;
  uint8_t ielen = 0;
  int decode_result;

  if (iei > 0) {
    CHECK_IEI_DECODER(iei, *buffer);
    decoded++;
  }

  IES_DECODE_U8( buffer, decoded, ielen );

  CHECK_LENGTH_DECODER(len - decoded, ielen);

  DECODE_U8( buffer+decoded, addr->pdn_type_value, decoded );
  //get 4 high bits
  addr->pdn_type_value &= 0b111;

  addr->pdn_address_information.len  = ielen;
  addr->pdn_address_information.data = buffer + decoded;

  decoded += ielen;

  return decoded;
}

