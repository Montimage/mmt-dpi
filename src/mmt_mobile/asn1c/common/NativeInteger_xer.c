/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeInteger.h>

/*
 * Decode the chunk of XML text encoding INTEGER.
 */
asn_dec_rval_t
NativeInteger_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **sptr,
                         const char *opt_mname, const void *buf_ptr,
                         size_t size) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    asn_dec_rval_t rval;
    INTEGER_t st;
    void *st_ptr = (void *)&st;
    void *native = *sptr;

    if(!native) {
        native = (*sptr = CALLOC(1, NativeInteger_field_width(specs)));
        if(!native) ASN__DECODE_FAILED;
    }

    memset(&st, 0, sizeof(st));
    rval = INTEGER_decode_xer(opt_codec_ctx, td, &st_ptr,
                              opt_mname, buf_ptr, size);
    if(rval.code == RC_OK) {
        if(NativeInteger_store_from_INTEGER(native, specs, &st)) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
        }
    } else {
        /*
         * Cannot restart from the middle;
         * there is no place to save state in the native type.
         * Request a continuation from the very beginning.
         */
        rval.consumed = 0;
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &st);
    return rval;
}

static const asn_INTEGER_enum_map_t *
NativeInteger_map_text2value(const asn_INTEGER_specifics_t *specs,
                             const char *lstart, const char *lstop) {
    int count = specs ? specs->map_count : 0;
    int i;

    if(!count) return NULL;
    while(lstart < lstop
          && (*lstart == 9 || *lstart == 10 || *lstart == 13 || *lstart == 32))
        lstart++;
    while(lstop > lstart
          && (lstop[-1] == 9 || lstop[-1] == 10 || lstop[-1] == 13
              || lstop[-1] == 32))
        lstop--;

    for(i = 0; i < count; i++) {
        const asn_INTEGER_enum_map_t *el = &specs->value2enum[i];
        if((size_t)(lstop - lstart) == el->enum_len
           && memcmp(lstart, el->enum_name, el->enum_len) == 0)
            return el;
    }
    return NULL;
}

static enum xer_pbd_rval
NativeInteger__xer_text_body_decode(const asn_TYPE_descriptor_t *td,
                                    void *sptr, const void *chunk_buf,
                                    size_t chunk_size) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    const asn_INTEGER_enum_map_t *el;

    el = NativeInteger_map_text2value(specs, (const char *)chunk_buf,
                                      (const char *)chunk_buf + chunk_size);
    if(!el)
        return XPBD_BROKEN_ENCODING;
    NativeInteger_store(sptr, specs, (uintmax_t)el->nat_value);
    return XPBD_BODY_CONSUMED;
}

asn_dec_rval_t
NativeInteger_decode_xer_text(const asn_codec_ctx_t *opt_codec_ctx,
                              const asn_TYPE_descriptor_t *td, void **sptr,
                              const char *opt_mname, const void *buf_ptr,
                              size_t size) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    void *native = *sptr;

    if(!native) {
        native = (*sptr = CALLOC(1, NativeInteger_field_width(specs)));
        if(!native) ASN__DECODE_FAILED;
    }

    return xer_decode_primitive(opt_codec_ctx, td,
        sptr, NativeInteger_field_width(specs), opt_mname,
        buf_ptr, size, NativeInteger__xer_text_body_decode);
}

asn_enc_rval_t
NativeInteger_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                         int ilevel, enum xer_encoder_flags_e flags,
                         asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    char scratch[32];  /* Enough for 64-bit int */
    asn_enc_rval_t er = {0,0,0};

    (void)ilevel;
    (void)flags;

    if(!sptr) ASN__ENCODE_FAILED;

    if(specs && specs->field_unsigned)
        er.encoded = snprintf(scratch, sizeof(scratch), "%ju",
                              NativeInteger_load_u(sptr, specs));
    else
        er.encoded = snprintf(scratch, sizeof(scratch), "%jd",
                              NativeInteger_load_s(sptr, specs));
    if(er.encoded <= 0 || (size_t)er.encoded >= sizeof(scratch)
        || cb(scratch, er.encoded, app_key) < 0)
        ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}

asn_enc_rval_t
NativeInteger_encode_xer_text(const asn_TYPE_descriptor_t *td,
                              const void *sptr, int ilevel,
                              enum xer_encoder_flags_e flags,
                              asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    asn_enc_rval_t er = {0,0,0};
    intmax_t value;
    const asn_INTEGER_enum_map_t *el;

    (void)ilevel;
    (void)flags;

    if(!sptr) ASN__ENCODE_FAILED;
    if(specs && specs->field_unsigned) {
        uintmax_t uvalue = NativeInteger_load_u(sptr, specs);
        if(uvalue > (uintmax_t)LONG_MAX)
            ASN__ENCODE_FAILED;
        value = (intmax_t)uvalue;
    } else {
        value = NativeInteger_load_s(sptr, specs);
    }

    el = INTEGER_map_value2enum(specs, (long)value);
    if(!el)
        ASN__ENCODE_FAILED;
    er.encoded = asn__format_to_callback(cb, app_key, "%s", el->enum_name);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
