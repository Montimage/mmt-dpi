#include <stdio.h>
#include <stdlib.h>
#include "mmt_common_internal_include.h"
#include "../include/mmt_tcpip_plugin.h"
#include "../include/mmt_tcpip_protocols.h"

/* Issue #212 (F-BUG-041): the ~160 inter-protocol registration calls in
 * init_tcpip_plugin() used to discard
 * register_classification_function_with_parent_protocol()'s return value, so a
 * partially registered classifier set reported full success and the affected
 * protocols silently never classified. mmt_register_classifier() performs one
 * checked registration and, on failure, prints a diagnostic naming the entry
 * and returns 0 — which REGISTER_INTER_PROTO_OR_FAIL propagates out of
 * init_tcpip_plugin() as an init failure. The function is exported
 * (non-static) so the phase0 classifier_init harness can drive it with a
 * deliberately bad entry and assert the init-failure signal. */
int mmt_register_classifier(uint32_t parent_proto,
        generic_classification_function classify_fn, int weight,
        const char *name) {
    if (!register_classification_function_with_parent_protocol(parent_proto,
                classify_fn, weight)) {
        fprintf(stderr,
            "Error registering classification function %s for parent protocol %u (weight %d)\n Exiting\n",
            (name != NULL) ? name : "?", (unsigned) parent_proto, weight);
        return 0;
    }
    return 1;
}

#define REGISTER_INTER_PROTO_OR_FAIL(parent, fn, w)                          \
    do {                                                                     \
        if (!mmt_register_classifier((parent), (fn), (w), #fn)) {            \
            return 0;                                                        \
        }                                                                    \
    } while (0)

int init_proto() {
    return init_tcpip_plugin();
}

int cleanup_proto(){
    return cleanup_tcpip_plugin();
}

int cleanup_tcpip_plugin(){
    // if(!cleanup_proto_tcp_struct()){
    //     fprintf(stderr, "No cleanup function for protocol proto_tcp\n");
    // }
    // M9 (issue #26): release the externally-loaded port-hint table. The IP-range
    // AVL trees (built-in + external) are freed by the library destructor via
    // _free_proto_avltrees().
    mmt_tcpip_free_external_port_map();
    return 1;
}

int init_tcpip_plugin() {
    int retval = 1;

    // B5 (remote-DoS hardening): every per-protocol registration below used to
    // call exit(0) on failure, killing the host process from inside a shared
    // library. They now `return 0` instead, so a failed initialization is
    // propagated as an error code to the caller (init_proto() ->
    // init_proto_fct() in load_plugin(), and init_extraction()) which can refuse
    // to continue instead of the whole process being torn down. The success
    // path is unchanged: it still falls through to `return retval` (== 1).

    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////PROTOCOL REGISTRATION (see proto_init_list.def) //////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    /* Built from proto_init_list.def — the same list that declares these
     * functions in mmt_common_internal_include.h, so a protocol cannot be
     * declared without being registered or vice versa (issue #148).
     * Registration order is the list's order and decides classifier chain
     * order; append new protocols at the end of the .def. */
    static const struct { int (*init)(void); const char *name; } proto_init_table[] = {
#define MMT_PROTO_INIT(init_fn, display_name) { init_fn, display_name },
#include "proto_init_list.def"
#undef MMT_PROTO_INIT
    };
    for (size_t i = 0; i < sizeof(proto_init_table)/sizeof(proto_init_table[0]); i++) {
        if (!proto_init_table[i].init()) {
            fprintf(stderr, "Error initializing protocol %s\n Exiting\n", proto_init_table[i].name);
            return 0;
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////END OF PROTOCOL REGISTRATION /////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////START OF INTER-PROTOCOL CLASSIFICATIONS ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////
    /***

        CLASSIFY PROTOCOL OVER TCP PROTOCOL

    ***/
    /**
     * WEIGHT
     * 20: highest priority
     * 30: popular
     * 40: Less popular
     * 50: Rare
     * 60: Special project: NDN
     */
     REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_http2, 9);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_http, 20);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_ssl, 20);

    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_dns, 30);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_imap, 30);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_smtp, 30);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_pop, 30);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_jabber, 30);

    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_netbios_tcp, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_ftp, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_bittorrent_tcp, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_ssh, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_smb, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_nfs, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_mysql, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_postgres, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_kerberos, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_redis, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_oracle, 40);

    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_stun_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_telnet, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_rtp_tcp, 50); //Check STUN before RTP
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_rdp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_mssql, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_sip, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_edonkey, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_fasttrack, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_gnutella, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_winmx, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_directconnect_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_msn_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_yahoo_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_oscar, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_applejuice, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_soulseek, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_irc, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_usenet, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_filetopia, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_manolito_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_imesh_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_mms, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_pando, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_tvants_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_sopcast_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_tvuplayer_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_ppstream_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_pplive_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_gadugadu, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_zattoo_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_qq_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_feidian_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_popo, 50); //BW: TODO: check this out
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_thunder_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_vnc, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_teamviewer_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_i23v5, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_socrates_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_steam, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_xbox, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_http_application_activesync, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_worldofwarcraft, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_flash, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_bgp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_secondlife_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_pcanywhere, 50); //BW: TODO: The classification of PCANYWHERE seems to be for UDP only, check this out
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_icecast, 50); //BW: TODO: Check out the classification --- dependence on http
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_shoutcast, 50); //BW: TODO: Check out the classification --- dependence on http
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_veohtv_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_openft, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_syslog, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_tds, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_direct_download_link, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_ipp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_ldap, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_warcraft3, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_xdmcp_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_pptp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_stealthnet, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_meebo, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_afp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_aimini_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_florensia_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_maplestory, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_dofus, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_world_of_kung_fu, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_fiesta, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_crossfire_tcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_guildwars, 50);
    /* issue #102: mmt_check_skype_tcp registration removed -- the classifier
     * matched on coincidental packet shape (no Skype protocol content
     * validation) and was a false-positive source; see proto_skype.c. */
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_citrix, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_dcerpc, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_spotify, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_rtsp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_tpkt, 50);
    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ndn, 60);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_ndn_http, 60);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_TCP, mmt_check_mqtt, 60);

    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp_control, 50);
    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp_data, 50);
    /***

        CLASSIFY PROTOCOL OVER UDP PROTOCOL

    ***/
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_quic, 30);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_mdns, 30); // Must be before mmt_check_dns
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_dns, 30);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_dhcp, 30);

    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_dropbox_udp, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_bittorrent_udp, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_ntp, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_nfs, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_ssdp, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_syslog, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_netbios_udp, 40);
    /* issue #102: mmt_check_skype_udp registration removed -- the classifier
     * matched on coincidental packet shape (no Skype protocol content
     * validation) and outranked STUN/RTP (weight 50), causing their flows
     * to be mislabeled Skype; see proto_skype.c. */
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_netflow, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_sflow, 40);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_vmware, 40);

    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_dhcpv6, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_stun_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_rtp_udp, 50); //Check STUN before RTP
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_sip, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_edonkey, 50); //BW: TODO: Edonkey classification seems limited to TCP! Check this out
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_gnutella, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_directconnect_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_msn_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_yahoo_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_oscar, 50); //BW: TODO: the classification of oscar seems to be for TCP only
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_jabber, 50); //BW: TODO: the classification of jabber seems to be for TCP only
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_gtp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_manolito_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_imesh_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_pando, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_tvants_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_sopcast_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_tvuplayer_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_ppstream_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_pplive_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_iax, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_mgcp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_gadugadu, 50); //BW: TODO: the classification of gadugadu seems to be for TCP only
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_zattoo_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_qq_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_feidian_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_popo, 50); //BW: TODO: check this out
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_thunder_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_teamviewer_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_socrates_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_halflife2, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_xbox, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_quake, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_battlefield, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_secondlife_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_pcanywhere, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_snmp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_kontiki, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_veohtv_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_ipp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_ldap, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_warcraft3, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_xdmcp_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_tftp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_aimini_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_florensia_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_crossfire_udp, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_armagetron, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_radius, 50);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_eclipse_tcf, 50);
    // register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ndn, 60);
    REGISTER_INTER_PROTO_OR_FAIL(PROTO_UDP, mmt_check_ndn_http, 60);
    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////////END OF INTER-PROTOCOL CLASSIFICATIONS ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////
#undef REGISTER_INTER_PROTO_OR_FAIL

    // M9 (issue #26): now that every tcpip protocol is registered (so protocol
    // names resolve), pull in any externally-supplied IP-range / port-hint data.
    // Both are no-ops unless MMT_DPI_IP_RANGES_FILE / MMT_DPI_PORT_MAP_FILE are
    // set, keeping the default classification byte-identical to the baseline.
    mmt_tcpip_load_external_ip_ranges();
    mmt_tcpip_load_external_port_map();

    return retval;
}

