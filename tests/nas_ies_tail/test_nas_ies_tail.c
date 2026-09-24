/*
 * test_nas_ies_tail.c
 *
 * Regression for issue #133: NAS IE fixed-size decoders bound by ielen
 * and remaining buffer length.
 *
 * Covers F-BUG-202,203,204,205,206,214,215:
 * - pdn_address_information.len validated against pdn_type minimum before UE-IP read (ielen 0..10)
 * - ielen=0 rejected before reading pdn_type
 * - GUTI(11)/IMSI/IMEI(8, issue #427) bounded by remaining len
 * - TAI list ielen>=6
 * - EPS QoS operator-precedence and buffer+decoded for QCI
 * - t3412value buffer+decoded in attach-accept
 * - negative decoder errors captured in signed ret before uint32 wrap
 *
 * Issue #208 adds F-BUG-081,083,084,085,088,090,120:
 * - nas_msg plain decode validates length before each header read
 *   (minimum-size security-protected PDU must not read past its end)
 * - every IE decoder validates pointer+length before its first read
 *   (iei>0 with a 1-byte buffer must not touch buffer[1])
 * - nas_tracking_area_identity honours its len argument
 * - eps_quality_of_service bit rates read buffer+decoded (four distinct bytes)
 * - nas_5g_decode rejects NULL/short input and never reinterprets the wire
 *
 * Verifies crafted Attach-Accept/Request tail cases (ielen 0..10 at buffer end)
 * pass without AddressSanitizer errors.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "emm/nas_emm_attach_accept.h"
#include "emm/nas_emm_attach_request.h"
#include "ies/pdn_address.h"
#include "ies/esp_mobile_identity.h"
#include "ies/tracking_area_identity.h"
#include "ies/tracking_area_identity_list.h"
#include "ies/eps_quality_of_service.h"
#include "nas_msg.h"
#include "nas_5g/nas_5g.h"

static int failures = 0;
static int checks = 0;
#define CHECK(desc, cond) do { \
    checks++; \
    if (cond) { printf("  ok   %s\n", desc); } \
    else      { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

static void test_pdn_tail(void) {
    printf("pdn_address tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[2];
        buf[0] = (uint8_t)ielen;
        nas_pdn_address_t addr; memset(&addr, 0, sizeof(addr));
        int ret = nas_decode_pdn_address(&addr, 0, buf, 1);
        char d[64]; snprintf(d, sizeof(d), "pdn ielen=%d len=1 returns error", ielen);
        CHECK(d, ret < 0);
        if (ielen >= 1) {
            uint8_t buf2[20]; memset(buf2, 0, sizeof(buf2));
            buf2[0] = (uint8_t)ielen;
            buf2[1] = NAS_PDN_VALUE_TYPE_IPV4;
            int ret2 = nas_decode_pdn_address(&addr, 0, buf2, 2);
            char d2[64]; snprintf(d2, sizeof(d2), "pdn ielen=%d len=2 trunc addr error", ielen);
            CHECK(d2, ret2 < 0);
        }
    }
}

static void test_mobile_identity_tail(void) {
    printf("eps_mobile_identity tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[20]; memset(buf, 0, sizeof(buf));
        buf[0] = (uint8_t)ielen;
        nas_eps_mobile_identity_t ident; memset(&ident, 0, sizeof(ident));
        int ret = nas_decode_eps_mobile_identity(&ident, 0, buf, 1);
        char d[64]; snprintf(d, sizeof(d), "mobile ielen=%d len=1 error", ielen);
        CHECK(d, ret < 0);
        if (ielen >= 1) {
            buf[1] = 0x01; // IMSI typeofidentity
            int ret2 = nas_decode_eps_mobile_identity(&ident, 0, buf, 2);
            char d2[64]; snprintf(d2, sizeof(d2), "mobile ielen=%d len=2 trunc payload error", ielen);
            CHECK(d2, ret2 < 0);
        }
    }
}

/* issue #427: a 15-digit IMSI is 8 value octets (TS 24.301 §9.9.3.12);
 * the decoder used to demand 9 and rejected every spec-valid IMSI. */
static void test_mobile_identity_imsi_15_digits(void) {
    printf("eps_mobile_identity 15-digit IMSI (8 octets):\n");
    const uint8_t buf[9] = { 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98 };
    nas_eps_mobile_identity_t ident; memset(&ident, 0, sizeof(ident));
    int ret = nas_decode_eps_mobile_identity(&ident, 0, buf, sizeof(buf));
    CHECK("imsi ielen=8 decodes (#427)", ret == 9);
    CHECK("imsi typeofidentity", ident.imsi.typeofidentity == EPS_MOBILE_IDENTITY_IMSI);
    CHECK("imsi digits 001010123456789",
          ident.imsi.digit1 == 0 && ident.imsi.digit2 == 0 && ident.imsi.digit3 == 1
          && ident.imsi.digit4 == 0 && ident.imsi.digit5 == 1 && ident.imsi.digit6 == 0
          && ident.imsi.digit9 == 3 && ident.imsi.digit14 == 8 && ident.imsi.digit15 == 9);
    memset(&ident, 0, sizeof(ident));
    CHECK("imsi truncated value rejected",
          nas_decode_eps_mobile_identity(&ident, 0, buf, sizeof(buf) - 1) < 0);
    uint8_t short_ie[9]; memcpy(short_ie, buf, sizeof(short_ie));
    short_ie[0] = 7;
    CHECK("imsi ielen=7 rejected",
          nas_decode_eps_mobile_identity(&ident, 0, short_ie, sizeof(short_ie)) < 0);
}

static void test_tai_tail(void) {
    printf("TAI list tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[20]; memset(buf, 0, sizeof(buf));
        buf[0] = (uint8_t)ielen;
        nas_tracking_area_identity_list_t lst; memset(&lst, 0, sizeof(lst));
        int ret = nas_decode_tracking_area_identity_list(&lst, 0, buf, 1);
        char d[64]; snprintf(d, sizeof(d), "tai ielen=%d len=1 error", ielen);
        CHECK(d, ret < 0);
    }
}

static void test_qos_tail(void) {
    printf("EPS QoS tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[20]; memset(buf, 0, sizeof(buf));
        buf[0] = (uint8_t)ielen;
        nas_eps_quality_of_service_t m; memset(&m, 0, sizeof(m));
        int ret = nas_decode_eps_quality_of_service(&m, 0, buf, 1);
        char d[64]; snprintf(d, sizeof(d), "qos ielen=%d len=1 error", ielen);
        CHECK(d, ret < 0);
        if (ielen >= 1) {
            int ret2 = nas_decode_eps_quality_of_service(&m, 0, buf, 2);
            char d2[64]; snprintf(d2, sizeof(d2), "qos ielen=%d len=2 no crash ret=%d", ielen, ret2);
            int expect_error = (ielen > 1);
            if (expect_error) CHECK(d2, ret2 < 0);
            else CHECK(d2, ret2 >= 0);
        }
    }
}

static void test_attach_request_tail(void) {
    printf("Attach Request tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[30]; memset(buf, 0, sizeof(buf));
        buf[0] = 0x01;
        buf[1] = (uint8_t)ielen;
        if (ielen >= 1) buf[2] = 0x01;
        nas_emm_attach_request_t msg; memset(&msg, 0, sizeof(msg));
        int len = (ielen >= 1) ? 3 : 2;
        int ret = nas_emm_decode_attach_request(&msg, buf, (uint32_t)len);
        char d[64]; snprintf(d, sizeof(d), "attach_req ielen=%d len=%d error", ielen, len);
        CHECK(d, ret < 0);
    }
}

static void test_attach_accept_tail(void) {
    printf("Attach Accept tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[30]; memset(buf, 0, sizeof(buf));
        buf[0] = 0x01;
        buf[1] = 0x02;
        buf[2] = (uint8_t)ielen;
        int len = 3;
        if (ielen >= 1) { buf[3] = 0x00; len = 4; }
        nas_emm_attach_accept_t acc; memset(&acc, 0, sizeof(acc));
        int ret = nas_emm_decode_attach_accept(&acc, buf, (uint32_t)len);
        char d[64]; snprintf(d, sizeof(d), "attach_acc ielen=%d len=%d error", ielen, len);
        CHECK(d, ret < 0);
    }
}

/* issue #208, F-BUG-083: iei>0 with a 1-byte buffer must not read buffer[1]
 * for ielen — validated before the first read (ASan red on old code). */
static void test_iei_len1(void) {
    printf("IE decoders: iei>0 len=1 tail:\n");
    uint8_t one[1] = { 0x50 };
    nas_eps_mobile_identity_t ident; memset(&ident, 0, sizeof(ident));
    CHECK("mobile_identity iei len=1 error",
          nas_decode_eps_mobile_identity(&ident, 0x50, one, 1) < 0);
    nas_pdn_address_t addr; memset(&addr, 0, sizeof(addr));
    CHECK("pdn_address iei len=1 error",
          nas_decode_pdn_address(&addr, 0x50, one, 1) < 0);
    nas_tracking_area_identity_list_t lst; memset(&lst, 0, sizeof(lst));
    CHECK("tai_list iei len=1 error",
          nas_decode_tracking_area_identity_list(&lst, 0x50, one, 1) < 0);
    nas_eps_quality_of_service_t qos; memset(&qos, 0, sizeof(qos));
    CHECK("eps_qos iei len=1 error",
          nas_decode_eps_quality_of_service(&qos, 0x50, one, 1) < 0);
    nas_tracking_area_identity_t tai; memset(&tai, 0, sizeof(tai));
    CHECK("tai iei len=1 error",
          nas_decode_tracking_area_identity(&tai, 0x50, one, 1) < 0);
}

/* issue #208, F-BUG-084: the single-TAI decoder ignored its len argument. */
static void test_tai_len(void) {
    printf("tracking_area_identity len honoured:\n");
    uint8_t buf[8] = { 0x21, 0x43, 0x65, 0x01, 0xAA, 0xBB, 0xCC, 0xDD };
    nas_tracking_area_identity_t tai;
    for (int len = 0; len <= 4; len++) {
        memset(&tai, 0, sizeof(tai));
        char d[64]; snprintf(d, sizeof(d), "tai len=%d error", len);
        CHECK(d, nas_decode_tracking_area_identity(&tai, 0, buf, (uint32_t)len) < 0);
    }
    memset(&tai, 0, sizeof(tai));
    int ret = nas_decode_tracking_area_identity(&tai, 0, buf, 5);
    CHECK("tai len=5 decodes 5", ret == 5);
    CHECK("tai mccdigit1", tai.mccdigit1 == 0x1);
    CHECK("tai mccdigit2", tai.mccdigit2 == 0x2);
    CHECK("tai tac", tai.tac == 0x01AA);
    /* with iei: 6 bytes needed */
    memset(&tai, 0, sizeof(tai));
    uint8_t buf_iei[6] = { 0x13, 0x21, 0x43, 0x65, 0x01, 0xAA };
    ret = nas_decode_tracking_area_identity(&tai, 0x13, buf_iei, 6);
    CHECK("tai iei len=6 decodes 6", ret == 6);
    CHECK("tai iei tac", tai.tac == 0x01AA);
    memset(&tai, 0, sizeof(tai));
    CHECK("tai iei len=5 error",
          nas_decode_tracking_area_identity(&tai, 0x13, buf_iei, 5) < 0);
}

/* issue #208, F-BUG-088: the four bit-rate DECODE_U8 calls read the bare
 * buffer — all four took buffer[0]. Assert they read distinct bytes. */
static void test_qos_bit_rates(void) {
    printf("EPS QoS bit rates read buffer+decoded:\n");
    nas_eps_quality_of_service_t m; memset(&m, 0, sizeof(m));
    /* no iei: ielen=5 covers qci + the four rate bytes */
    uint8_t buf[6] = { 5, 0x09, 0x11, 0x22, 0x33, 0x44 };
    int ret = nas_decode_eps_quality_of_service(&m, 0, buf, sizeof(buf));
    CHECK("qos ielen=5 decodes", ret == 6);
    CHECK("qos bit_rates_present", m.bit_rates_present == 1);
    CHECK("qos bit_rates_ext absent", m.bit_rates_ext_present == 0);
    CHECK("qos max ul", m.bit_rates.max_bit_rate_for_ul  == 0x11);
    CHECK("qos max dl", m.bit_rates.max_bit_rate_for_dl  == 0x22);
    CHECK("qos guar ul", m.bit_rates.guar_bit_rate_for_ul == 0x33);
    CHECK("qos guar dl", m.bit_rates.guar_bit_rate_for_dl == 0x44);
    CHECK("qos four rates differ",
          m.bit_rates.max_bit_rate_for_ul != m.bit_rates.max_bit_rate_for_dl
          && m.bit_rates.max_bit_rate_for_dl != m.bit_rates.guar_bit_rate_for_ul
          && m.bit_rates.guar_bit_rate_for_ul != m.bit_rates.guar_bit_rate_for_dl);
    /* extended rates: ielen=9 covers qci + 4 + 4 */
    memset(&m, 0, sizeof(m));
    uint8_t buf2[10] = { 9, 0x09, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    ret = nas_decode_eps_quality_of_service(&m, 0, buf2, sizeof(buf2));
    CHECK("qos ielen=9 decodes", ret == 10);
    CHECK("qos bit_rates_ext present", m.bit_rates_ext_present == 1);
    CHECK("qos ext max ul", m.bit_rates_ext.max_bit_rate_for_ul  == 0x55);
    CHECK("qos ext guar dl", m.bit_rates_ext.guar_bit_rate_for_dl == 0x88);
}

/* issue #208, F-BUG-081: a minimum-size security-protected PDU (header only,
 * no plain payload) must not have its absent first byte read. */
static void test_nas_msg_min(void) {
    printf("nas_msg minimum-length PDUs:\n");
    nas_msg_t m;
    /* EMM pd(0x7) + integrity-protected(0x1) => 0x17; exactly 6-byte header */
    uint8_t prot[6] = { 0x17, 0xAA, 0xBB, 0xCC, 0xDD, 0x01 };
    memset(&m, 0, sizeof(m));
    CHECK("protected header-only pdu error",
          nas_decode(&m, prot, sizeof(prot)) < 0);
    uint8_t one[1] = { 0x07 };
    memset(&m, 0, sizeof(m));
    CHECK("plain len=1 error", nas_decode(&m, one, 1) < 0);
    uint8_t emm2[2] = { 0x07, 0x41 };
    memset(&m, 0, sizeof(m));
    CHECK("plain len=2 error", nas_decode(&m, emm2, 2) < 0);
}

/* issue #208, F-BUG-120: nas_5g_decode bounds + byte-wise field mapping. */
static void test_nas5g_decode(void) {
    printf("nas_5g_decode bounds and fields:\n");
    nas_5g_msg_t m;
    uint8_t buf[4] = { 0x7E, 0x03, 0x41, 0x99 };
    CHECK("nas5g NULL msg", !nas_5g_decode(NULL, buf, 4));
    CHECK("nas5g NULL buffer", !nas_5g_decode(&m, NULL, 4));
    memset(&m, 0, sizeof(m));
    CHECK("nas5g len=0 rejected", !nas_5g_decode(&m, buf, 0));
    CHECK("nas5g 5GMM len=2 rejected", !nas_5g_decode(&m, buf, 2));
    /* issue #427: the plain 5GMM header is 3 octets — a minimal 5GMM
     * message (e.g. Authentication Response, type 0x57) must decode, and
     * the union octet past the header is zeroed, not left stale. */
    uint8_t auth_resp[3] = { 0x7E, 0x00, 0x57 };
    memset(&m, 0xAA, sizeof(m));
    CHECK("nas5g 5GMM len=3 decodes (#427)", nas_5g_decode(&m, auth_resp, 3));
    CHECK("nas5g 5GMM len=3 message_type", m.mmm.message_type == 0x57);
    CHECK("nas5g 5GMM len=3 tail octet zeroed", m.smm.message_type == 0);
    /* the 5GSM header is 4 octets: a 3-octet 5GSM message is still short */
    uint8_t smm[4] = { 0x2E, 0x01, 0x02, 0xC1 };
    CHECK("nas5g 5GSM len=3 rejected", !nas_5g_decode(&m, smm, 3));
    memset(&m, 0xAA, sizeof(m));
    CHECK("nas5g 5GSM len=4 decodes", nas_5g_decode(&m, smm, 4));
    CHECK("nas5g 5GSM message_type", m.smm.message_type == 0xC1);
    memset(&m, 0xAA, sizeof(m));
    CHECK("nas5g len=4 decodes", nas_5g_decode(&m, buf, 4));
    CHECK("nas5g protocol_discriminator", m.protocol_discriminator == 0x7E);
    CHECK("nas5g smm.message_type", m.smm.message_type == 0x99);
    CHECK("nas5g smm.procedure_transaction_identity",
          m.smm.procedure_transaction_identity == 0x41);
    CHECK("nas5g mmm.message_type", m.mmm.message_type == 0x41);
    /* mmm.security_header_type is a bitfield whose nibble order depends on
     * whether the including TU saw __LITTLE_ENDIAN__ — not asserted here. */
}

int main(void) {
    test_pdn_tail();
    test_mobile_identity_tail();
    test_mobile_identity_imsi_15_digits();
    test_tai_tail();
    test_qos_tail();
    test_attach_request_tail();
    test_attach_accept_tail();
    test_iei_len1();
    test_tai_len();
    test_qos_bit_rates();
    test_nas_msg_min();
    test_nas5g_decode();
    printf("\n%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
