/*
 * File:   mmt_common_internal_include.h
 * Author: montimage
 *
 * Created on 16 octobre 2012, 17:10
 */

#ifndef MMT_COMMON_INTERNAL_INCLUDE_H
#define	MMT_COMMON_INTERNAL_INCLUDE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "mmt_core.h"
#include "mmt_tcpip_internal_defs_macros.h"
#include "mmt_tcpip_plugin_structs.h"

#include "../include/mmt_tcpip_plugin.h"
#include "../include/mmt_tcpip_protocols.h"
#include "protocols/ip_session_id_management.h"
#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "protocols/ip.h"
#include "protocols/ipv6.h"
#include "protocols/udp.h"
#include "protocols/tcp.h"
#include "protocols/icmp.h"
#include "protocols/icmp6.h"
#include "protocols/gre.h"
#include "protocols/rtp.h"
#include "protocols/http.h"
#include "protocols/batman.h"
#include "protocols/ospf.h"
#include "protocols/sctp.h"

#include "mmt_tcpip_utils.h"
#include "mmt_tcpip_plugin_internal.h"

#define MMT_MAX_DNS_REQUESTS      16
#define MMT_PORT_MATCH(srcp, dstp, port) (((port == srcp) || (port == dstp)) ? 1 : 0)
    // unsigned int mmt_get_protocol_by_port_number(uint8_t proto, uint16_t sport, uint16_t dport);
    unsigned int mmt_guess_protocol_by_port_number(ipacket_t * ipacket);

    uint32_t get_proto_id_from_address(ipacket_t * ipacket);
    uint32_t get_proto_id_by_hostname(ipacket_t * ipacket, char *hostname, u_int hostname_len);

    // /* define memory callback function */
    // void mmt_classify_me_bittorrent(ipacket_t * ipacket, unsigned index);
    // /* edonkey entry function*/
    // void mmt_classify_me_edonkey(ipacket_t * ipacket, unsigned index);
    // /* fasttrack entry function*/
    // void mmt_classify_me_fasttrack_tcp(ipacket_t * ipacket, unsigned index);
    // /* gnutella entry function*/
    // void mmt_classify_me_gnutella(ipacket_t * ipacket, unsigned index);
    // /* winmx entry function*/
    // void mmt_classify_me_winmx_tcp(ipacket_t * ipacket, unsigned index);
    // /* directconnect entry function*/
    // void mmt_classify_me_directconnect(ipacket_t * ipacket, unsigned index);
    // /* applejuice entry function*/
    // void mmt_classify_me_applejuice_tcp(ipacket_t * ipacket, unsigned index);
    // /* i23v5 entry function */
    // void mmt_classify_me_i23v5(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_socrates(ipacket_t * ipacket, unsigned index);
    // /* soulseek entry function*/
    // // void mmt_classify_me_soulseek_tcp(ipacket_t * ipacket, unsigned index);
    // /* msn entry function*/
    // void mmt_classify_me_msn(ipacket_t * ipacket, unsigned index);
    // /* yahoo entry function*/
    // void mmt_classify_me_yahoo(ipacket_t * ipacket, unsigned index);
    // /* oscar entry function*/
    // void mmt_classify_me_oscar(ipacket_t * ipacket, unsigned index);
    // /* jabber entry function*/
    // void mmt_classify_me_jabber_tcp(ipacket_t * ipacket, unsigned index);
    // /* irc entry function*/
    // void mmt_classify_me_irc_tcp(ipacket_t * ipacket, unsigned index);
    // /* sip entry, used for tcp and udp !!! */
    // void mmt_classify_me_sip(ipacket_t * ipacket, unsigned index);
    // /* DirectDownloadLink entry */
    // void mmt_classify_me_ddl(ipacket_t * ipacket, unsigned index);
    // /* Mail POP entry */
    // void mmt_classify_me_pop(ipacket_t * ipacket, unsigned index);
    // /* IMAP entry */
    // void mmt_classify_me_imap(ipacket_t * ipacket, unsigned index);
    // /* Mail SMTP entry */
    // void mmt_classify_me_smtp(ipacket_t * ipacket, unsigned index);
    // /* HTTP entry */
    // void mmt_classify_me_http(ipacket_t * ipacket, unsigned index);
    // /* FTP entry */
    // void mmt_classify_me_ftp(ipacket_t * ipacket, unsigned index);
    // /* NDN entry */
    // // void mmt_classify_me_ndn(ipacket_t * ipacket, unsigned index);
    // /* USENET entry */
    // void mmt_classify_me_usenet(ipacket_t * ipacket, unsigned index);
    // /* DNS entry */
    // int mmt_classify_me_dns(ipacket_t * ipacket, unsigned index);
    // /* RTSP entry */
    // void mmt_classify_me_rtsp(ipacket_t * ipacket, unsigned index);
    // /* filetopia entry */
    // void mmt_classify_me_filetopia(ipacket_t * ipacket, unsigned index);
    // /* manolito entry */
    // void mmt_classify_me_manolito(ipacket_t * ipacket, unsigned index);
    // /* imesh entry */
    // void mmt_classify_me_imesh(ipacket_t * ipacket, unsigned index);
    // /* SSL entry */
    // // void mmt_classify_me_ssl(ipacket_t * ipacket, unsigned index);
    // /* flash entry */
    // void mmt_classify_me_flash(ipacket_t * ipacket, unsigned index);
    // /* mms entry */
    // void mmt_classify_me_mms(ipacket_t * ipacket, unsigned index);
    // /* icecast entry */
    // void mmt_classify_me_icecast(ipacket_t * ipacket, unsigned index);
    // /* shoutcast entry */
    // void mmt_classify_me_shoutcast(ipacket_t * ipacket, unsigned index);
    // /* veohtv entry */
    // void mmt_classify_me_veohtv(ipacket_t * ipacket, unsigned index);
    // /* openft entry */
    // void mmt_classify_me_openft(ipacket_t * ipacket, unsigned index);
    // /* stun entry */
    // void mmt_classify_me_stun(ipacket_t * ipacket, unsigned index);
    // /* Pando entry */
    // void mmt_classify_me_pando(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_tvants(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_sopcast(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_tvuplayer(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_ppstream(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_pplive(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_iax(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_mgcp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_gadugadu(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_zattoo(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_qq(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_feidian(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_ssh(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_popo(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_thunder(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_activesync(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_vnc(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_dhcp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_steam(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_halflife2(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_xbox(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_smb(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_telnet(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_ntp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_nfs(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_rtp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_ssdp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_worldofwarcraft(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_postgres(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_mysql(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_bgp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_quake(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_battlefield(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_secondlife(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_pcanywhere(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_rdp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_snmp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_kontiki(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_syslog(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_tds(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_netbios(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_mdns(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_ipp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_ldap(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_warcraft3(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_kerberos(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_xdmcp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_tftp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_mssql(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_pptp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_stealthnet(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_dhcpv6(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_meebo(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_afp(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_aimini(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_florensia(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_maplestory(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_dofus(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_world_of_kung_fu(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_fiesta(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_crossfire(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_guildwars(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_armagetron(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_dropbox(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_citrix(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_dcerpc(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_netflow(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_sflow(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_radius(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_wsus(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_teamview(ipacket_t * ipacket, unsigned index);
    // void mmt_classify_me_spotify(ipacket_t * ipacket, unsigned index);

    ////////////////////////////////////////////////////////////////////////////
    /////////////Inter-Protocol classification functions ///////////////////////
    ////////////////////////////////////////////////////////////////////////////

    int mmt_check_http(ipacket_t * ipacket, unsigned index);
    int mmt_check_ssl(ipacket_t * ipacket, unsigned index);
    int mmt_check_stun_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_stun_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_rtp_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_rtp_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_rdp(ipacket_t * ipacket, unsigned index);
    int mmt_check_sip(ipacket_t * ipacket, unsigned index);
    int mmt_check_bittorrent_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_bittorrent_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_edonkey(ipacket_t * ipacket, unsigned index);
    int mmt_check_fasttrack(ipacket_t * ipacket, unsigned index);
    int mmt_check_gnutella(ipacket_t * ipacket, unsigned index);
    int mmt_check_winmx(ipacket_t * ipacket, unsigned index);
    int mmt_check_directconnect_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_directconnect_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_msn_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_msn_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_yahoo_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_yahoo_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_oscar(ipacket_t * ipacket, unsigned index);
    int mmt_check_applejuice(ipacket_t * ipacket, unsigned index);
    int mmt_check_soulseek(ipacket_t * ipacket, unsigned index);
    int mmt_check_irc(ipacket_t * ipacket, unsigned index);
    int mmt_check_jabber(ipacket_t * ipacket, unsigned index);
    int mmt_check_pop(ipacket_t * ipacket, unsigned index);
    int mmt_check_imap(ipacket_t * ipacket, unsigned index);
    int mmt_check_smtp(ipacket_t * ipacket, unsigned index);
    int mmt_check_ftp(ipacket_t * ipacket, unsigned index);
    int mmt_check_ndn(ipacket_t * ipacket, unsigned index);
    int mmt_check_gtp(ipacket_t * ipacket, unsigned index);
    int mmt_check_ndn_http(ipacket_t * ipacket, unsigned index);
    int mmt_check_usenet(ipacket_t * ipacket, unsigned index);
    int mmt_check_dns(ipacket_t * ipacket, unsigned index);
    int mmt_check_rtsp(ipacket_t * ipacket, unsigned index);
    int mmt_check_filetopia(ipacket_t * ipacket, unsigned index);
    int mmt_check_manolito_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_manolito_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_imesh_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_imesh_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_mms(ipacket_t * ipacket, unsigned index);
    int mmt_check_pando(ipacket_t * ipacket, unsigned index);
    int mmt_check_tvants_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_tvants_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_sopcast_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_sopcast_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_tvuplayer_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_tvuplayer_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_ppstream_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_ppstream_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_pplive_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_pplive_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_iax(ipacket_t * ipacket, unsigned index);
    int mmt_check_mgcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_gadugadu(ipacket_t * ipacket, unsigned index);
    int mmt_check_zattoo_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_zattoo_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_qq_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_qq_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_feidian_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_feidian_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_ssh(ipacket_t * ipacket, unsigned index);
    int mmt_check_popo(ipacket_t * ipacket, unsigned index);
    int mmt_check_thunder_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_thunder_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_vnc(ipacket_t * ipacket, unsigned index);
    int mmt_check_teamviewer_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_teamviewer_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_dhcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_i23v5(ipacket_t * ipacket, unsigned index);
    int mmt_check_socrates_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_socrates_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_steam(ipacket_t * ipacket, unsigned index);
    int mmt_check_halflife2(ipacket_t * ipacket, unsigned index);
    int mmt_check_xbox(ipacket_t * ipacket, unsigned index);
    int mmt_check_http_application_activesync(ipacket_t * ipacket, unsigned index);
    int mmt_check_smb(ipacket_t * ipacket, unsigned index);
    int mmt_check_telnet(ipacket_t * ipacket, unsigned index);
    int mmt_check_ntp(ipacket_t * ipacket, unsigned index);
    int mmt_check_nfs(ipacket_t * ipacket, unsigned index);
    int mmt_check_ssdp(ipacket_t * ipacket, unsigned index);
    int mmt_check_worldofwarcraft(ipacket_t * ipacket, unsigned index);
    int mmt_check_flash(ipacket_t * ipacket, unsigned index);
    int mmt_check_postgres(ipacket_t * ipacket, unsigned index);
    int mmt_check_mysql(ipacket_t * ipacket, unsigned index);
    int mmt_check_bgp(ipacket_t * ipacket, unsigned index);
    int mmt_check_quake(ipacket_t * ipacket, unsigned index);
    int mmt_check_battlefield(ipacket_t * ipacket, unsigned index);
    int mmt_check_secondlife_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_secondlife_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_pcanywhere(ipacket_t * ipacket, unsigned index);
    int mmt_check_snmp(ipacket_t * ipacket, unsigned index);
    int mmt_check_kontiki(ipacket_t * ipacket, unsigned index);
    int mmt_check_icecast(ipacket_t * ipacket, unsigned index);
    int mmt_check_shoutcast(ipacket_t * ipacket, unsigned index);
    int mmt_check_veohtv_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_veohtv_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_kerberos(ipacket_t * ipacket, unsigned index);
    int mmt_check_openft(ipacket_t * ipacket, unsigned index);
    int mmt_check_syslog(ipacket_t * ipacket, unsigned index);
    int mmt_check_tds(ipacket_t * ipacket, unsigned index);
    int mmt_check_direct_download_link(ipacket_t * ipacket, unsigned index);
    int mmt_check_netbios_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_netbios_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_mdns(ipacket_t * ipacket, unsigned index);
    int mmt_check_ipp(ipacket_t * ipacket, unsigned index);
    int mmt_check_ldap(ipacket_t * ipacket, unsigned index);
    int mmt_check_warcraft3(ipacket_t * ipacket, unsigned index);
    int mmt_check_xdmcp_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_xdmcp_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_tftp(ipacket_t * ipacket, unsigned index);
    int mmt_check_mssql(ipacket_t * ipacket, unsigned index);
    int mmt_check_pptp(ipacket_t * ipacket, unsigned index);
    int mmt_check_stealthnet(ipacket_t * ipacket, unsigned index);
    int mmt_check_dhcpv6(ipacket_t * ipacket, unsigned index);
    int mmt_check_meebo(ipacket_t * ipacket, unsigned index);
    int mmt_check_afp(ipacket_t * ipacket, unsigned index);
    int mmt_check_aimini_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_aimini_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_florensia_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_florensia_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_maplestory(ipacket_t * ipacket, unsigned index);
    int mmt_check_dofus(ipacket_t * ipacket, unsigned index);
    int mmt_check_world_of_kung_fu(ipacket_t * ipacket, unsigned index);
    int mmt_check_fiesta(ipacket_t * ipacket, unsigned index);
    int mmt_check_crossfire_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_crossfire_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_guildwars(ipacket_t * ipacket, unsigned index);
    int mmt_check_armagetron(ipacket_t * ipacket, unsigned index);
    int mmt_check_dropbox_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_skype_tcp(ipacket_t * ipacket, unsigned index);
    int mmt_check_skype_udp(ipacket_t * ipacket, unsigned index);
    int mmt_check_radius(ipacket_t * ipacket, unsigned index);
    int mmt_check_citrix(ipacket_t * ipacket, unsigned index);
    int mmt_check_dcerpc(ipacket_t * ipacket, unsigned index);
    int mmt_check_netflow(ipacket_t * ipacket, unsigned index);
    int mmt_check_sflow(ipacket_t * ipacket, unsigned index);
    int mmt_check_spotify(ipacket_t * ipacket, unsigned index);
    int mmt_check_quic(ipacket_t * ipacket, unsigned index);
    int mmt_check_oracle(ipacket_t * ipacket, unsigned index);
    int mmt_check_redis(ipacket_t * ipacket, unsigned index);
    int mmt_check_vmware(ipacket_t * ipacket, unsigned index);
    int mmt_check_eclipse_tcf(ipacket_t * ipacket, unsigned index);
    int mmt_check_tpkt(ipacket_t * ipacket, unsigned index);
    // int mmt_check_ftp_control(ipacket_t * ipacket, unsigned index);
    // int mmt_check_ftp_data(ipacket_t * ipacket, unsigned index);
    int mmt_check_mqtt(ipacket_t * ipacket, unsigned index);
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
 int mmt_check_http2(ipacket_t * ipacket, unsigned proto_index) ;
    /**
     * macro for getting the string len of a static string
     *
     * use it instead of strlen to avoid runtime calculations
     */
#define MMT_STATICSTRING_LEN(s) (sizeof(s) - 1)

    /** macro to compare 2 IPv6 addresses with each other to identify the "smaller" IPv6 address  */
    ////////////////// PROTOCOL INIT DECLARATIONS //////////////////////////////
    /* Protocol init declarations: generated from proto_init_list.def, which is
     * also what builds proto_init_table[] in configured_protocols.c. Keeping
     * both in one list is what makes adding a protocol a single-line edit
     * (issue #148). */
#define MMT_PROTO_INIT(init_fn, display_name) int init_fn();
#include "proto_init_list.def"
#undef MMT_PROTO_INIT

    /* Defined in proto_dtls.c but deliberately absent from proto_init_list.def:
     * no entry has ever registered it, so DTLS is not part of the classifier
     * chain. Declared here to keep the definition prototyped. Tracked
     * separately — registering it would change classification results. */
    int init_proto_dtls_struct();

#ifdef	__cplusplus
}
#endif

#endif	/* MMT_COMMON_INTERNAL_INCLUDE_H */

