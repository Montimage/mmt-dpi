#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_direct_download_link_add_connection(ipacket_t * ipacket) {
    struct mmt_internal_tcpip_session_struct *flow = ipacket->internal_packet->flow;

    mmt_internal_add_connection(ipacket, PROTO_DIRECT_DOWNLOAD_LINK, MMT_CORRELATED_PROTOCOL);

    flow->l4.tcp.ddlink_server_direction = ipacket->session->last_packet_direction;
}

/* Direct-download hosts (issue #547, F-CLEAN-008): the suffixes the
 * generated 640-line suffix trie of search_ddl_domains() matched, one row per
 * accepting branch, in the trie's order. A Host line matches a row when it
 * ends with the suffix (after the ":port" strip) and the character before
 * the suffix is ' ' or '.', so "www.rapidshare.com" matches "rapidshare.com"
 * while "rapidshare.com" alone or "myrapidshare.com" does not — exactly the
 * trie's test. */
#define DDL_HOST_SUFFIX(s) { (s), sizeof(s) - 1 }
static const struct ddl_host_suffix {
    const char *suffix;
    uint16_t len;
} ddl_host_suffixes[] = {
    DDL_HOST_SUFFIX("4shared.com"),
    DDL_HOST_SUFFIX("filecloud.com"),
    DDL_HOST_SUFFIX("files-upload.com"),
    DDL_HOST_SUFFIX("megaupload.com"),
    DDL_HOST_SUFFIX("rapidupload.com"),
    DDL_HOST_SUFFIX("turboupload.com"),
    DDL_HOST_SUFFIX("badongo.com"),
    DDL_HOST_SUFFIX("fileho.com"),
    DDL_HOST_SUFFIX("bestsharing.com"),
    DDL_HOST_SUFFIX("quicksharing.com"),
    DDL_HOST_SUFFIX("uploading.com"),
    DDL_HOST_SUFFIX("sharebig.com"),
    DDL_HOST_SUFFIX("bigfilez.com"),
    DDL_HOST_SUFFIX("chinamofile.com"),
    DDL_HOST_SUFFIX("mofile.com"),
    DDL_HOST_SUFFIX("hotfile.com"),
    DDL_HOST_SUFFIX("keepmyfile.com"),
    DDL_HOST_SUFFIX("savefile.com"),
    DDL_HOST_SUFFIX("sendmefile.com"),
    DDL_HOST_SUFFIX("sharebigfile.com"),
    DDL_HOST_SUFFIX("up-file.com"),
    DDL_HOST_SUFFIX("easy-share.com"),
    DDL_HOST_SUFFIX("fast-share.com"),
    DDL_HOST_SUFFIX("live-share.com"),
    DDL_HOST_SUFFIX("ftp2share.com"),
    DDL_HOST_SUFFIX("gigeshare.com"),
    DDL_HOST_SUFFIX("megashare.com"),
    DDL_HOST_SUFFIX("rapidshare.com"),
    DDL_HOST_SUFFIX("mediafire.com"),
    DDL_HOST_SUFFIX("gigasize.com"),
    DDL_HOST_SUFFIX("sendspace.com"),
    DDL_HOST_SUFFIX("sharebee.com"),
    DDL_HOST_SUFFIX("sharebigflie.com"),
    DDL_HOST_SUFFIX("fileserve.com"),
    DDL_HOST_SUFFIX("depositfiles.com"),
    DDL_HOST_SUFFIX("megashares.com"),
    DDL_HOST_SUFFIX("fileupyours.com"),
    DDL_HOST_SUFFIX("filefactory.com"),
    DDL_HOST_SUFFIX("filefront.com"),
    DDL_HOST_SUFFIX("uploadingit.com"),
    DDL_HOST_SUFFIX("yourfilehost.com"),
    DDL_HOST_SUFFIX("mytempdir.com"),
    DDL_HOST_SUFFIX("uploadpower.com"),
    DDL_HOST_SUFFIX("mega.1280.com"),
    DDL_HOST_SUFFIX("filesonic.com"),
    DDL_HOST_SUFFIX("badongo.net"),
    DDL_HOST_SUFFIX("fast-load.net"),
    DDL_HOST_SUFFIX("file-upload.net"),
    DDL_HOST_SUFFIX("simpleupload.net"),
    DDL_HOST_SUFFIX("wiiupload.net"),
    DDL_HOST_SUFFIX("filesend.net"),
    DDL_HOST_SUFFIX("filer.net"),
    DDL_HOST_SUFFIX("livedepot.net"),
    DDL_HOST_SUFFIX("mofile.net"),
    DDL_HOST_SUFFIX("odsiebie.najlepsze.net"),
    DDL_HOST_SUFFIX("zshare.net"),
    DDL_HOST_SUFFIX("data.hu"),
    DDL_HOST_SUFFIX("filearchiv.ru"),
    DDL_HOST_SUFFIX("filepost.ru"),
    DDL_HOST_SUFFIX("ifolder.ru"),
    DDL_HOST_SUFFIX("filehost.tv"),
    DDL_HOST_SUFFIX("filesafe.to"),
    DDL_HOST_SUFFIX("sharebase.to"),
    DDL_HOST_SUFFIX("files.to"),
    DDL_HOST_SUFFIX("file-upload.to"),
    DDL_HOST_SUFFIX("load.to"),
    DDL_HOST_SUFFIX("uploaded.to"),
    DDL_HOST_SUFFIX("leteckaposta.cz"),
    DDL_HOST_SUFFIX("yourfiles.biz"),
    DDL_HOST_SUFFIX("netload.in"),
    DDL_HOST_SUFFIX("4shared.vn"),
    DDL_HOST_SUFFIX("megashare.vn"),
    DDL_HOST_SUFFIX("rapidshare.de"),
    DDL_HOST_SUFFIX("ultrashare.de"),
    DDL_HOST_SUFFIX("uploadyourfiles.de"),
    DDL_HOST_SUFFIX("speedshare.org"),
};

/* 1 when host[0..len) ends with a ddl_host_suffixes row on a label boundary */
static uint8_t ddl_host_matches(const uint8_t *host, uint16_t len) {
    size_t i;
    for (i = 0; i < sizeof(ddl_host_suffixes) / sizeof(ddl_host_suffixes[0]); i++) {
        const struct ddl_host_suffix *row = &ddl_host_suffixes[i];
        if (len >= row->len + 1
                && mmt_memcmp(&host[len - row->len], row->suffix, row->len) == 0
                && (host[len - row->len - 1] == ' ' || host[len - row->len - 1] == '.')) {
            return 1;
        }
    }
    return 0;
}

/*
  return 0 if nothing has been detected
  return 1 if it is a megaupload packet
 */
uint8_t search_ddl_domains(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    uint16_t filename_start = 0;
    uint8_t i = 1;
    uint16_t host_line_len_without_port;

    if (packet->payload_packet_len < 100) {
        goto end_ddl_nothing_found;
    }



    if (mmt_memcmp(packet->payload, "POST ", 5) == 0) {
        filename_start = 5; // POST
    } else if (mmt_memcmp(packet->payload, "GET ", 4) == 0) {
        filename_start = 4; // GET
    } else {
        goto end_ddl_nothing_found;
    }
    // parse packet
    mmt_parse_packet_line_info(ipacket);

    if (packet->host_line.ptr == NULL) {
        goto end_ddl_nothing_found;
    }


    if (packet->line[0].len < 9 + filename_start
            || mmt_memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) != 0) {
        goto end_ddl_nothing_found;
    }
    // first see if we have ':port' at the end of the line
    host_line_len_without_port = packet->host_line.len;
    if (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] >= '0'
            && packet->host_line.ptr[packet->host_line.len - i] <= '9') {
        i = 2;
        while (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] >= '0'
                && packet->host_line.ptr[host_line_len_without_port - i] <= '9') {
            i++;
        }
        if (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] == ':') {
            host_line_len_without_port = host_line_len_without_port - i;
        }
    }
    if (ddl_host_matches(packet->host_line.ptr, host_line_len_without_port)) {
        goto end_ddl_found;
    }

    /* This is the hard way. We do this in order to find the download of services when other
       domains are involved. This is not significant if ddl is blocked. --> then the link can not be started because
       the ads are not viewed. But when ddl is only limited then the download is the important part.
     */

end_ddl_nothing_found:
    return 0;

end_ddl_found:
    mmt_int_direct_download_link_add_connection(ipacket);
    return 1;
}

void mmt_classify_ddl(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    // do not detect again if it is already ddl
    if (packet->detected_protocol_stack[0] != PROTO_DIRECT_DOWNLOAD_LINK) {
        if (search_ddl_domains(ipacket) != 0) {
            return;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DIRECT_DOWNLOAD_LINK);
    }

}

int mmt_check_direct_download_link(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_ddl(ipacket, index);
    }
    return 4;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_direct_download_link_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DIRECT_DOWNLOAD_LINK, PROTO_DIRECT_DOWNLOAD_LINK_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
                PROTO_DIRECT_DOWNLOAD_LINK, PROTO_DIRECT_DOWNLOAD_LINK);
        
        return register_protocol(protocol_struct, PROTO_DIRECT_DOWNLOAD_LINK);
    } else {
        return 0;
    }
}


