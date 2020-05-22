#include "../util/decoder.h"
#include "nas_esm_activate_default_eps_bearer_context_request.h"

int nas_esm_decode_activate_default_eps_bearer_context_request(nas_esm_activate_default_eps_bearer_context_request_t *msg, const uint8_t *buffer, uint32_t len){
  uint32_t decoded = 0;
  int decoded_result = 0;

  // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
  CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MINIMUM_LENGTH, len);

  /* Decoding mandatory fields */
  decoded_result = nas_decode_eps_quality_of_service(&msg->eps_qos, 0, buffer + decoded, len - decoded);
  CHECK_RESULT_DECODER(decoded_result, decoded );

  decoded_result = nas_decode_octet_string(&msg->access_point_name, 1, buffer + decoded, len - decoded);
  CHECK_RESULT_DECODER(decoded_result, decoded );

  decoded_result = nas_decode_pdn_address(&msg->pdn_address, 0, buffer + decoded, len - decoded);
  CHECK_RESULT_DECODER(decoded_result, decoded );

  /* Decoding optional fields */

  return decoded;
}
