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
 * - IMSIs shorter than 14 digits (ielen 4..7) decode (issue #443)
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
 * Issue #335 adds:
 * - TAI list: all three list types and several partial lists, the whole
 *   IE consumed, malformed partial lists bounded by the IE length
 * - Attach Accept: every optional IE walked by its format (TV, TLV,
 *   TLV-E, type 1), the GUTI found after a multi-TAC TAI list
 *
 * Verifies crafted Attach-Accept/Request tail cases (ielen 0..10 at buffer end)
 * pass without AddressSanitizer errors.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
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
}

/* issue #443: IMSIs shorter than 14 digits are fewer value octets
 * (TS 24.301 §9.9.3.12 / TS 24.008 §10.5.1.4); they used to be rejected.
 * Digits past the IMSI's end read back as the 0xF end mark. */
static void test_mobile_identity_imsi_short(void) {
    printf("eps_mobile_identity short IMSIs (issue #443):\n");
    nas_eps_mobile_identity_t ident;

    /* 13 digits 0010101234567: odd, 7 octets */
    const uint8_t imsi13[8] = { 0x07, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76 };
    memset(&ident, 0, sizeof(ident));
    CHECK("13-digit imsi (ielen=7) decodes",
          nas_decode_eps_mobile_identity(&ident, 0, imsi13, sizeof(imsi13)) == 8);
    CHECK("13-digit imsi digits",
          ident.imsi.digit1 == 0 && ident.imsi.digit3 == 1 && ident.imsi.digit7 == 1
          && ident.imsi.digit8 == 2 && ident.imsi.digit12 == 6 && ident.imsi.digit13 == 7);
    CHECK("13-digit imsi: digits 14..15 are end marks",
          ident.imsi.digit14 == 0xf && ident.imsi.digit15 == 0xf);

    /* 12 digits 001010123456: even, 7 octets, filler in the last one */
    const uint8_t imsi12[8] = { 0x07, 0x01, 0x10, 0x10, 0x10, 0x32, 0x54, 0xf6 };
    memset(&ident, 0, sizeof(ident));
    CHECK("12-digit imsi (ielen=7, filler) decodes",
          nas_decode_eps_mobile_identity(&ident, 0, imsi12, sizeof(imsi12)) == 8);
    CHECK("12-digit imsi digits and end marks",
          ident.imsi.digit12 == 6 && ident.imsi.digit13 == 0xf
          && ident.imsi.digit14 == 0xf && ident.imsi.digit15 == 0xf);

    /* 6 digits 001010 (MCC + 2-digit MNC): even, 4 octets */
    const uint8_t imsi6[5] = { 0x04, 0x01, 0x10, 0x10, 0xf0 };
    memset(&ident, 0, sizeof(ident));
    CHECK("6-digit imsi (ielen=4) decodes",
          nas_decode_eps_mobile_identity(&ident, 0, imsi6, sizeof(imsi6)) == 5);
    CHECK("6-digit imsi: digit7 is an end mark",
          ident.imsi.digit6 == 0 && ident.imsi.digit7 == 0xf);

    /* the length octet bounds the read: a trailing IE is not taken as digits */
    const uint8_t imsi13_tail[9] = { 0x07, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x55 };
    memset(&ident, 0, sizeof(ident));
    CHECK("short imsi does not read past ielen",
          nas_decode_eps_mobile_identity(&ident, 0, imsi13_tail, sizeof(imsi13_tail)) == 8
          && ident.imsi.digit14 == 0xf);

    uint8_t bad[8];
    memcpy(bad, imsi12, sizeof(bad));
    bad[7] = 0x76; /* even indicator without the filler */
    CHECK("even imsi without filler rejected",
          nas_decode_eps_mobile_identity(&ident, 0, bad, sizeof(bad)) < 0);
    memcpy(bad, imsi13, sizeof(bad));
    bad[4] = 0xf1; /* end mark inside the digit string */
    CHECK("end mark inside the digits rejected",
          nas_decode_eps_mobile_identity(&ident, 0, bad, sizeof(bad)) < 0);
    const uint8_t imsi5[4] = { 0x03, 0x09, 0x10, 0x10 };
    CHECK("imsi below MCC+MNC (ielen=3) rejected",
          nas_decode_eps_mobile_identity(&ident, 0, imsi5, sizeof(imsi5)) < 0);
    /* more than 15 digits is not an IMSI (and reading only 8 of the 9
     * octets would desync the caller's offset) */
    const uint8_t imsi17[10] = { 0x09, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x11 };
    CHECK("imsi ielen=9 rejected",
          nas_decode_eps_mobile_identity(&ident, 0, imsi17, sizeof(imsi17)) < 0);
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


/* issue #335: TAI list types 00/01/10, several partial lists, IE size */
static void test_tai_list_types(void) {
    printf("TAI list types and partial lists (#335):\n");
    nas_tracking_area_identity_list_t lst;

    /* type 00, 3 TACs of PLMN 001/01 (ielen = 1 + 3 + 6 = 10) */
    const uint8_t t00[] = { 10, 0x02, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x05, 0x12, 0x34 };
    memset(&lst, 0, sizeof(lst));
    CHECK("type00 consumes the whole IE",
          nas_decode_tracking_area_identity_list(&lst, 0, t00, sizeof(t00)) == 11);
    CHECK("type00 header", lst.typeoflist == TRACKING_AREA_IDENTITY_LIST_ONE_PLMN_NON_CONSECUTIVE_TACS
          && lst.numberofelements == 2 && lst.partial_lists == 1 && !lst.malformed);
    CHECK("type00 3 TAIs", lst.tai_count == 3 && lst.tai[0].tac == 0x0001
          && lst.tai[1].tac == 0x0005 && lst.tai[2].tac == 0x1234);
    CHECK("type00 PLMN digits", lst.tai[2].mccdigit1 == 0 && lst.tai[2].mccdigit2 == 0
          && lst.tai[2].mccdigit3 == 1 && lst.tai[2].mncdigit1 == 0
          && lst.tai[2].mncdigit2 == 1 && lst.tai[2].mncdigit3 == 0xF);
    CHECK("type00 first TAI mirrored", lst.tac == 0x0001 && lst.mccdigit3 == 1);

    /* type 01, 4 consecutive TACs starting at 0x00FE (ielen = 6) */
    const uint8_t t01[] = { 6, 0x23, 0x21, 0x43, 0x65, 0x00, 0xFE };
    memset(&lst, 0, sizeof(lst));
    CHECK("type01 decodes 7",
          nas_decode_tracking_area_identity_list(&lst, 0, t01, sizeof(t01)) == 7);
    CHECK("type01 expanded to 4 TAIs", lst.tai_count == 4 && lst.tai[0].tac == 0x00FE
          && lst.tai[3].tac == 0x0101 && lst.tai[3].mccdigit1 == 1 && lst.tai[3].mncdigit1 == 5);

    /* type 10 (2 PLMNs) followed by a type 00 partial list with one TAC
     * (ielen = 1 + 10 + 1 + 3 + 2 = 17), IEI 0x54 */
    const uint8_t t10[] = { 0x54, 17,
        0x41, 0x00, 0xF1, 0x10, 0x00, 0x07,   0x13, 0x00, 0x62, 0x00, 0x08,
        0x00, 0x21, 0xF3, 0x54, 0xAB, 0xCD };
    memset(&lst, 0, sizeof(lst));
    CHECK("type10 + type00 decodes 19 with IEI",
          nas_decode_tracking_area_identity_list(&lst, 0x54, t10, sizeof(t10)) == 19);
    CHECK("two partial lists, three TAIs", lst.partial_lists == 2 && lst.tai_count == 3 && !lst.malformed);
    CHECK("type10 header kept from first partial list",
          lst.typeoflist == TRACKING_AREA_IDENTITY_LIST_MANY_PLMNS && lst.numberofelements == 1);
    CHECK("type10 second PLMN", lst.tai[1].mccdigit1 == 3 && lst.tai[1].mccdigit2 == 1
          && lst.tai[1].mccdigit3 == 0 && lst.tai[1].mncdigit2 == 6
          && lst.tai[1].mncdigit1 == 2 && lst.tai[1].tac == 0x0008);
    CHECK("type00 after type10", lst.tai[2].mccdigit1 == 1 && lst.tai[2].mncdigit1 == 4
          && lst.tai[2].tac == 0xABCD);

    /* partial list overrunning the IE: type 00 claims 3 TACs, ielen 8 */
    const uint8_t over[] = { 8, 0x02, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x05, 0xEE, 0xEE };
    memset(&lst, 0, sizeof(lst));
    CHECK("overrunning partial list: IE still consumed",
          nas_decode_tracking_area_identity_list(&lst, 0, over, sizeof(over)) == 9);
    CHECK("overrunning partial list flagged, nothing stored",
          lst.malformed && lst.tai_count == 0 && lst.partial_lists == 0);

    /* reserved type 11 after a valid partial list */
    const uint8_t rsv[] = { 7, 0x20, 0x00, 0xF1, 0x10, 0x00, 0x09, 0x60 };
    memset(&lst, 0, sizeof(lst));
    CHECK("reserved type decodes IE",
          nas_decode_tracking_area_identity_list(&lst, 0, rsv, sizeof(rsv)) == 8);
    CHECK("reserved type flagged, prefix kept", lst.malformed && lst.tai_count == 1
          && lst.tai[0].tac == 0x0009);

    /* 17 TAIs: two consecutive lists of 16 and 1 — the 17th is refused */
    const uint8_t many[] = { 12, 0x2F, 0x00, 0xF1, 0x10, 0x00, 0x00,
                                 0x20, 0x00, 0xF1, 0x10, 0x01, 0x00 };
    memset(&lst, 0, sizeof(lst));
    CHECK("17 TAIs decodes IE",
          nas_decode_tracking_area_identity_list(&lst, 0, many, sizeof(many)) == 13);
    CHECK("17 TAIs capped at 16 and flagged", lst.tai_count == 16 && lst.malformed
          && lst.tai[15].tac == 15);

    /* number of elements 11111 (unused) is read as 16 (TS 24.301 §9.9.3.33) */
    const uint8_t unused_n[] = { 6, 0x3F, 0x00, 0xF1, 0x10, 0x00, 0x10 };
    memset(&lst, 0, sizeof(lst));
    CHECK("unused number of elements decodes IE",
          nas_decode_tracking_area_identity_list(&lst, 0, unused_n, sizeof(unused_n)) == 7);
    CHECK("unused number of elements read as 16", lst.tai_count == 16 && !lst.malformed
          && lst.tai[15].tac == 0x001F);

    /* a malformed first partial list leaves no stale flat fields */
    memset(&lst, 0xA5, sizeof(lst));
    CHECK("stale struct: overrunning list decodes IE",
          nas_decode_tracking_area_identity_list(&lst, 0, over, sizeof(over)) == 9);
    CHECK("stale struct: flat fields cleared", lst.malformed && lst.tai_count == 0
          && lst.tac == 0 && lst.typeoflist == 0 && lst.mccdigit1 == 0);

    /* the IE length is still checked against the buffer */
    memset(&lst, 0, sizeof(lst));
    CHECK("ielen beyond buffer rejected",
          nas_decode_tracking_area_identity_list(&lst, 0, t00, sizeof(t00) - 1) < 0);
}

/* A plain Attach Accept (after the 2-byte EMM header) with a 2-TAC TAI list:
 * the old decoder consumed only the first TAI (7 bytes of the 9-byte list)
 * and read the ESM container from the wrong offset. */
static const uint8_t attach_accept_body[] = {
    0x02,                                           /* EPS attach result */
    0x21,                                           /* T3412 */
    8, 0x01, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x02, /* TAI list: 2 TACs */
    0x00, 0x03, 0x52, 0x01, 0xC1,                   /* ESM container (LV-E) */
    0x50, 11, 0xF6, 0x00, 0xF1, 0x10, 0x80, 0x01, 0x01,
          0xDE, 0xAD, 0xBE, 0xEF,                   /* GUTI */
    0x13, 0x00, 0xF1, 0x10, 0x12, 0x34,             /* LAI (TV) */
    0x23, 5, 0xF4, 0x11, 0x22, 0x33, 0x44,          /* MS identity */
    0x53, 0x10,                                     /* EMM cause */
    0x17, 0x2C,                                     /* T3402 */
    0x59, 0x49,                                     /* T3423 */
    0x4A, 3, 0x00, 0xF2, 0x10,                      /* equivalent PLMNs */
    0x34, 3, 0x02, 0x11, 0x99,                      /* emergency numbers */
    0x64, 1, 0x01,                                  /* network features */
    0xF2,                                           /* additional update result */
    0x5E, 1, 0x21,                                  /* T3412 extended */
    0x7A, 0x00, 0x02, 0xAA, 0xBB,                   /* TLV-E, not decoded */
    0x66, 2, 0xCC, 0xDD,                            /* unknown TLV */
    0xC1,                                           /* unknown type-1 */
    0x50, 11, 0xF6, 0x00, 0xF1, 0x10, 0x80, 0x01, 0x01,
          0x00, 0x00, 0x00, 0x01,                   /* repeated GUTI */
};

static void test_attach_accept_full(void) {
    printf("Attach Accept full extraction (#335):\n");
    nas_emm_attach_accept_t acc;
    const uint32_t len = sizeof(attach_accept_body);
    memset(&acc, 0, sizeof(acc));
    int ret = nas_emm_decode_attach_accept(&acc, attach_accept_body, len);
    CHECK("whole message consumed", ret == (int)len);
    CHECK("TAI list has 2 TAIs", acc.tailist.tai_count == 2 && acc.tailist.tai[1].tac == 2);
    CHECK("ESM container at the right offset", acc.esm_message_container.len == 3
          && acc.esm_message_container.data == attach_accept_body + 13);
    CHECK("GUTI decoded, first occurrence kept",
          (acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_GUTI)
          && acc.guti.guti.typeofidentity == EPS_MOBILE_IDENTITY_GUTI
          && acc.guti.guti.mtmsi == 0xDEADBEEF);
    CHECK("LAI", (acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_LAI) && acc.lai.len == 5
          && acc.lai.data[3] == 0x12 && acc.lai.data[4] == 0x34);
    CHECK("MS identity", (acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_MS_IDENTITY)
          && acc.ms_identity.len == 5 && acc.ms_identity.data[4] == 0x44);
    CHECK("EMM cause / T3402 / T3423",
          acc.emm_cause == 0x10 && acc.t3402value == 0x2C && acc.t3423value == 0x49
          && (acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_EMM_CAUSE)
          && (acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_T3402_VALUE)
          && (acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_T3423_VALUE));
    CHECK("equivalent PLMNs", acc.equivalent_plmns.len == 3 && acc.equivalent_plmns.data[1] == 0xF2);
    CHECK("emergency number list", acc.emergency_number_list.len == 3
          && acc.emergency_number_list.data[2] == 0x99);
    CHECK("EPS network feature support", acc.eps_network_feature_support.len == 1
          && acc.eps_network_feature_support.data[0] == 0x01);
    CHECK("additional update result", (acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_ADDITIONAL_UPDATE_RESULT)
          && acc.additional_update_result == 2);
    CHECK("T3412 extended", (acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_T3412_EXTENDED_VALUE)
          && acc.t3412_extended_value.len == 1 && acc.t3412_extended_value.data[0] == 0x21);
    CHECK("TLV-E, unknown TLV and unknown type-1 skipped", acc.unknown_ies == 3);
    CHECK("not truncated", !(acc.present & NAS_EMM_ATTACH_ACCEPT_TRUNCATED));

    /* every truncation of the optional part: never an error, never an
     * over-read (ASan), fields before the cut stay decoded */
    int bad = 0;
    for (uint32_t cut = 16; cut < len; cut++) {
        uint8_t *copy = malloc(cut);            /* exact-size heap copy */
        memcpy(copy, attach_accept_body, cut);
        memset(&acc, 0, sizeof(acc));
        ret = nas_emm_decode_attach_accept(&acc, copy, cut);
        if (ret < 0 || ret > (int)cut || acc.esm_message_container.len != 3)
            bad++;
        free(copy);
    }
    CHECK("every optional-part truncation decodes the mandatory part", bad == 0);

    /* GUTI cut inside its value: flagged, no half-filled identity */
    memset(&acc, 0, sizeof(acc));
    ret = nas_emm_decode_attach_accept(&acc, attach_accept_body, 25);
    CHECK("truncated GUTI flagged", ret == 16 && (acc.present & NAS_EMM_ATTACH_ACCEPT_TRUNCATED)
          && !(acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_GUTI) && acc.guti.guti.mtmsi == 0);

    /* GUTI with a wrong length: skipped whole, identity cleared */
    uint8_t bad_guti[] = { 0x02, 0x21, 6, 0x20, 0x00, 0xF1, 0x10, 0x00, 0x01,
        0x00, 0x00, 0x50, 4, 0xF6, 0x00, 0xF1, 0x10, 0x53, 0x07 };
    memset(&acc, 0, sizeof(acc));
    ret = nas_emm_decode_attach_accept(&acc, bad_guti, sizeof(bad_guti));
    CHECK("short GUTI skipped, next IE decoded", ret == (int)sizeof(bad_guti)
          && !(acc.present & NAS_EMM_ATTACH_ACCEPT_HAS_GUTI)
          && acc.guti.guti.typeofidentity == 0 && acc.emm_cause == 0x07);
}

/* The same message wrapped in an integrity-protected+ciphered NAS PDU, as
 * s1ap_common.c decodes it to extract the M-TMSI. */
static void test_attach_accept_in_nas_pdu(void) {
    printf("Attach Accept through nas_decode (#335):\n");
    uint8_t pdu[6 + 2 + sizeof(attach_accept_body)];
    const uint8_t hdr[8] = { 0x27, 0x11, 0x22, 0x33, 0x44, 0x01, 0x07, 0x42 };
    memcpy(pdu, hdr, sizeof(hdr));
    memcpy(pdu + sizeof(hdr), attach_accept_body, sizeof(attach_accept_body));
    nas_msg_t m; memset(&m, 0, sizeof(m));
    CHECK("protected attach accept decodes", nas_decode(&m, pdu, sizeof(pdu)) == (int)sizeof(pdu));
    CHECK("M-TMSI after multi-TAC TAI list",
          m.protected_msg.msg.emm.header.message_type == NAS_EMM_ATTACH_ACCEPT
          && m.protected_msg.msg.emm.attach_accept.guti.guti.mtmsi == 0xDEADBEEF);
}

int main(void) {
    test_pdn_tail();
    test_mobile_identity_tail();
    test_mobile_identity_imsi_15_digits();
    test_mobile_identity_imsi_short();
    test_tai_tail();
    test_qos_tail();
    test_attach_request_tail();
    test_attach_accept_tail();
    test_iei_len1();
    test_tai_len();
    test_qos_bit_rates();
    test_nas_msg_min();
    test_nas5g_decode();
    test_tai_list_types();
    test_attach_accept_full();
    test_attach_accept_in_nas_pdu();
    printf("\n%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
