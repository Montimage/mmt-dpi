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

#define MMT_PORT_MATCH(srcp, dstp, port) (((port == srcp) || (port == dstp)) ? 1 : 0)

    unsigned int mmt_get_protocol_by_port_number(uint8_t proto, uint32_t shost, uint16_t sport, uint32_t dhost, uint16_t dport);

    unsigned int mmt_guess_protocol_by_port_number(ipacket_t * ipacket);

    uint32_t get_proto_id_from_address(ipacket_t * ipacket);
    uint32_t get_proto_id_by_hostname(ipacket_t * ipacket, char *hostname, u_int hostname_len);

    /* define memory callback function */
    void mmt_classify_me_bittorrent(ipacket_t * ipacket, unsigned index);
    /* edonkey entry function*/
    void mmt_classify_me_edonkey(ipacket_t * ipacket, unsigned index);
    /* fasttrack entry function*/
    void mmt_classify_me_fasttrack_tcp(ipacket_t * ipacket, unsigned index);
    /* gnutella entry function*/
    void mmt_classify_me_gnutella(ipacket_t * ipacket, unsigned index);
    /* winmx entry function*/
    void mmt_classify_me_winmx_tcp(ipacket_t * ipacket, unsigned index);
    /* directconnect entry function*/
    void mmt_classify_me_directconnect(ipacket_t * ipacket, unsigned index);
    /* applejuice entry function*/
    void mmt_classify_me_applejuice_tcp(ipacket_t * ipacket, unsigned index);
    /* i23v5 entry function */
    void mmt_classify_me_i23v5(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_socrates(ipacket_t * ipacket, unsigned index);
    /* soulseek entry function*/
    void mmt_classify_me_soulseek_tcp(ipacket_t * ipacket, unsigned index);
    /* msn entry function*/
    void mmt_classify_me_msn(ipacket_t * ipacket, unsigned index);
    /* yahoo entry function*/
    void mmt_classify_me_yahoo(ipacket_t * ipacket, unsigned index);
    /* oscar entry function*/
    void mmt_classify_me_oscar(ipacket_t * ipacket, unsigned index);
    /* jabber entry function*/
    void mmt_classify_me_jabber_tcp(ipacket_t * ipacket, unsigned index);
    /* irc entry function*/
    void mmt_classify_me_irc_tcp(ipacket_t * ipacket, unsigned index);
    /* sip entry, used for tcp and udp !!! */
    void mmt_classify_me_sip(ipacket_t * ipacket, unsigned index);
    /* DirectDownloadLink entry */
    void mmt_classify_me_ddl(ipacket_t * ipacket, unsigned index);
    /* Mail POP entry */
    void mmt_classify_me_pop(ipacket_t * ipacket, unsigned index);
    /* IMAP entry */
    void mmt_classify_me_imap(ipacket_t * ipacket, unsigned index);
    /* Mail SMTP entry */
    void mmt_classify_me_smtp(ipacket_t * ipacket, unsigned index);
    /* HTTP entry */
    void mmt_classify_me_http(ipacket_t * ipacket, unsigned index);
    /* FTP entry */
    void mmt_classify_me_ftp(ipacket_t * ipacket, unsigned index);
    /* NDN entry */
    // void mmt_classify_me_ndn(ipacket_t * ipacket, unsigned index);
    /* USENET entry */
    void mmt_classify_me_usenet(ipacket_t * ipacket, unsigned index);
    /* DNS entry */
    void mmt_classify_me_dns(ipacket_t * ipacket, unsigned index);
    /* RTSP entry */
    void mmt_classify_me_rtsp(ipacket_t * ipacket, unsigned index);
    /* filetopia entry */
    void mmt_classify_me_filetopia(ipacket_t * ipacket, unsigned index);
    /* manolito entry */
    void mmt_classify_me_manolito(ipacket_t * ipacket, unsigned index);
    /* imesh entry */
    void mmt_classify_me_imesh(ipacket_t * ipacket, unsigned index);
    /* SSL entry */
    void mmt_classify_me_ssl(ipacket_t * ipacket, unsigned index);
    /* flash entry */
    void mmt_classify_me_flash(ipacket_t * ipacket, unsigned index);
    /* mms entry */
    void mmt_classify_me_mms(ipacket_t * ipacket, unsigned index);
    /* icecast entry */
    void mmt_classify_me_icecast(ipacket_t * ipacket, unsigned index);
    /* shoutcast entry */
    void mmt_classify_me_shoutcast(ipacket_t * ipacket, unsigned index);
    /* veohtv entry */
    void mmt_classify_me_veohtv(ipacket_t * ipacket, unsigned index);
    /* openft entry */
    void mmt_classify_me_openft(ipacket_t * ipacket, unsigned index);
    /* stun entry */
    void mmt_classify_me_stun(ipacket_t * ipacket, unsigned index);
    /* Pando entry */
    void mmt_classify_me_pando(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_tvants(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_sopcast(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_tvuplayer(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_ppstream(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_pplive(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_iax(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_mgcp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_gadugadu(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_zattoo(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_qq(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_feidian(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_ssh(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_popo(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_thunder(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_activesync(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_vnc(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_dhcp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_steam(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_halflife2(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_xbox(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_smb(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_telnet(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_ntp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_nfs(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_rtp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_ssdp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_worldofwarcraft(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_postgres(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_mysql(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_bgp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_quake(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_battlefield(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_secondlife(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_pcanywhere(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_rdp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_snmp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_kontiki(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_syslog(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_tds(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_netbios(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_mdns(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_ipp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_ldap(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_warcraft3(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_kerberos(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_xdmcp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_tftp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_mssql(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_pptp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_stealthnet(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_dhcpv6(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_meebo(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_afp(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_aimini(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_florensia(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_maplestory(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_dofus(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_world_of_kung_fu(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_fiesta(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_crossfire(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_guildwars(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_armagetron(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_dropbox(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_skype(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_citrix(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_dcerpc(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_netflow(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_sflow(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_radius(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_wsus(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_teamview(ipacket_t * ipacket, unsigned index);
    void mmt_classify_me_spotify(ipacket_t * ipacket, unsigned index);

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
    int mmt_check_usenet(ipacket_t * ipacket, unsigned index);
    int mmt_check_dns(ipacket_t * ipacket, unsigned index);
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

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////

    /**
     * macro for getting the string len of a static string
     *
     * use it instead of strlen to avoid runtime calculations
     */
#define MMT_STATICSTRING_LEN(s) (sizeof(s) - 1)

    /** macro to compare 2 IPv6 addresses with each other to identify the "smaller" IPv6 address  */
#define MMT_COMPARE_IPV6_ADDRESS(x,y)  \
  ((((uint64_t *)(x))[0]) < (((uint64_t *)(y))[0]) || ( (((uint64_t *)(x))[0]) == (((uint64_t *)(y))[0]) && (((uint64_t *)(x))[1]) < (((uint64_t *)(y))[1])) )

    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////START OF GENERATED CODE --- DO NOT MODIFY ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    /////////// PLUGIN INIT FOR PROTO_163 //////////////////
    int init_proto_163_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_360 //////////////////
    int init_proto_360_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_302_FOUND //////////////////
    int init_proto_302_found_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_360BUY //////////////////
    int init_proto_360buy_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_56 //////////////////
    int init_proto_56_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_8021Q //////////////////
    int init_proto_8021q_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_888 //////////////////
    int init_proto_888_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ABOUT //////////////////
    int init_proto_about_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ADCASH //////////////////
    int init_proto_adcash_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ADDTHIS //////////////////
    int init_proto_addthis_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ADF //////////////////
    int init_proto_adf_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ADOBE //////////////////
    int init_proto_adobe_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AFP //////////////////
    int init_proto_afp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AH //////////////////
    int init_proto_ah_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AIM //////////////////
    int init_proto_aim_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AIMINI //////////////////
    int init_proto_aimini_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ALIBABA //////////////////
    int init_proto_alibaba_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ALIPAY //////////////////
    int init_proto_alipay_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ALLEGRO //////////////////
    int init_proto_allegro_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AMAZON //////////////////
    int init_proto_amazon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AMEBLO //////////////////
    int init_proto_ameblo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ANCESTRY //////////////////
    int init_proto_ancestry_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ANGRYBIRDS //////////////////
    int init_proto_angrybirds_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ANSWERS //////////////////
    int init_proto_answers_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AOL //////////////////
    int init_proto_aol_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_APPLE //////////////////
    int init_proto_apple_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_APPLEJUICE //////////////////
    int init_proto_applejuice_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ARMAGETRON //////////////////
    int init_proto_armagetron_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ARP //////////////////
    int init_proto_arp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ASK //////////////////
    int init_proto_ask_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AVG //////////////////
    int init_proto_avg_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AVI //////////////////
    int init_proto_avi_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AWEBER //////////////////
    int init_proto_aweber_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AWS //////////////////
    int init_proto_aws_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BABYLON //////////////////
    int init_proto_babylon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BADOO //////////////////
    int init_proto_badoo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BAIDU //////////////////
    int init_proto_baidu_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BANKOFAMERICA //////////////////
    int init_proto_bankofamerica_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BARNESANDNOBLE //////////////////
    int init_proto_barnesandnoble_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BATMAN //////////////////
    int init_proto_batman_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BATTLEFIELD //////////////////
    int init_proto_battlefield_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BATTLENET //////////////////
    int init_proto_battlenet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BBB //////////////////
    int init_proto_bbb_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BBC_ONLINE //////////////////
    int init_proto_bbc_online_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BESTBUY //////////////////
    int init_proto_bestbuy_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BETFAIR //////////////////
    int init_proto_betfair_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BGP //////////////////
    int init_proto_bgp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BIBLEGATEWAY //////////////////
    int init_proto_biblegateway_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BILD //////////////////
    int init_proto_bild_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BING //////////////////
    int init_proto_bing_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BITTORRENT //////////////////
    int init_proto_bittorrent_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BLEACHERREPORT //////////////////
    int init_proto_bleacherreport_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BLOGFA //////////////////
    int init_proto_blogfa_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BLOGGER //////////////////
    int init_proto_blogger_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BLOGSPOT //////////////////
    int init_proto_blogspot_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BODYBUILDING //////////////////
    int init_proto_bodybuilding_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BOOKING //////////////////
    int init_proto_booking_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CBSSPORTS //////////////////
    int init_proto_cbssports_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CENT //////////////////
    int init_proto_cent_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CHANGE //////////////////
    int init_proto_change_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CHASE //////////////////
    int init_proto_chase_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CHESS //////////////////
    int init_proto_chess_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CHINAZ //////////////////
    int init_proto_chinaz_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CITRIX //////////////////
    int init_proto_citrix_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CITRIXONLINE //////////////////
    int init_proto_citrixonline_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CLICKSOR //////////////////
    int init_proto_clicksor_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CNN //////////////////
    int init_proto_cnn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CNZZ //////////////////
    int init_proto_cnzz_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_COMCAST //////////////////
    int init_proto_comcast_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CONDUIT //////////////////
    int init_proto_conduit_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_COPYSCAPE //////////////////
    int init_proto_copyscape_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CORREIOS //////////////////
    int init_proto_correios_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CRAIGSLIST //////////////////
    int init_proto_craigslist_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CROSSFIRE //////////////////
    int init_proto_crossfire_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DAILYMAIL //////////////////
    int init_proto_dailymail_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DAILYMOTION //////////////////
    int init_proto_dailymotion_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DCERPC //////////////////
    int init_proto_dcerpc_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DIRECT_DOWNLOAD_LINK //////////////////
    int init_proto_direct_download_link_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DEVIANTART //////////////////
    int init_proto_deviantart_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DHCP //////////////////
    int init_proto_dhcp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DHCPV6 //////////////////
    int init_proto_dhcpv6_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DIGG //////////////////
    int init_proto_digg_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DIRECTCONNECT //////////////////
    int init_proto_directconnect_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DNS //////////////////
    int init_proto_dns_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DOFUS //////////////////
    int init_proto_dofus_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DONANIMHABER //////////////////
    int init_proto_donanimhaber_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DOUBAN //////////////////
    int init_proto_douban_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DOUBLECLICK //////////////////
    int init_proto_doubleclick_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DROPBOX //////////////////
    int init_proto_dropbox_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EBAY //////////////////
    int init_proto_ebay_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EDONKEY //////////////////
    int init_proto_edonkey_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EGP //////////////////
    int init_proto_egp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EHOW //////////////////
    int init_proto_ehow_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EKSISOZLUK //////////////////
    int init_proto_eksisozluk_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ELECTRONICSARTS //////////////////
    int init_proto_electronicsarts_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ESP //////////////////
    int init_proto_esp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ESPN //////////////////
    int init_proto_espn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ETHERNET //////////////////
    int init_proto_ethernet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ETSY //////////////////
    int init_proto_etsy_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EUROPA //////////////////
    int init_proto_europa_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EUROSPORT //////////////////
    int init_proto_eurosport_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FACEBOOK //////////////////
    int init_proto_facebook_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FACETIME //////////////////
    int init_proto_facetime_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FASTTRACK //////////////////
    int init_proto_fasttrack_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FC2 //////////////////
    int init_proto_fc2_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FEIDIAN //////////////////
    int init_proto_feidian_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FIESTA //////////////////
    int init_proto_fiesta_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FILETOPIA //////////////////
    int init_proto_filetopia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FIVERR //////////////////
    int init_proto_fiverr_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FLASH //////////////////
    int init_proto_flash_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FLICKR //////////////////
    int init_proto_flickr_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FLORENSIA //////////////////
    int init_proto_florensia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FOURSQUARE //////////////////
    int init_proto_foursquare_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FOX //////////////////
    int init_proto_fox_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FREE //////////////////
    int init_proto_free_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FTP //////////////////
    int init_proto_ftp_struct();
    /////////// PLUGIN INIT FOR PROTO_NDN //////////////////
    int init_proto_ndn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GADUGADU //////////////////
    int init_proto_gadugadu_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GAMEFAQS //////////////////
    int init_proto_gamefaqs_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GAMESPOT //////////////////
    int init_proto_gamespot_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GAP //////////////////
    int init_proto_gap_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GARANTI //////////////////
    int init_proto_garanti_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GAZETEVATAN //////////////////
    int init_proto_gazetevatan_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GIGAPETA //////////////////
    int init_proto_gigapeta_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GITHUB //////////////////
    int init_proto_github_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GITTIGIDIYOR //////////////////
    int init_proto_gittigidiyor_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GLOBO //////////////////
    int init_proto_globo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GMAIL //////////////////
    int init_proto_gmail_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GNUTELLA //////////////////
    int init_proto_gnutella_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GOOGLE_MAPS //////////////////
    int init_proto_google_maps_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GO //////////////////
    int init_proto_go_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GODADDY //////////////////
    int init_proto_godaddy_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GOO //////////////////
    int init_proto_goo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GOOGLE //////////////////
    int init_proto_google_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GOOGLE_USER_CONTENT //////////////////
    int init_proto_google_user_content_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GOSMS //////////////////
    int init_proto_gosms_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GRE //////////////////
    int init_proto_gre_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GROOVESHARK //////////////////
    int init_proto_grooveshark_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GROUPON //////////////////
    int init_proto_groupon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GTALK //////////////////
    int init_proto_gtalk_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GTP //////////////////
    int init_proto_gtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GTP2 //////////////////
    int init_proto_gtp2_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GUARDIAN //////////////////
    int init_proto_guardian_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GUILDWARS //////////////////
    int init_proto_guildwars_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HABERTURK //////////////////
    int init_proto_haberturk_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HAO123 //////////////////
    int init_proto_hao123_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HEPSIBURADA //////////////////
    int init_proto_hepsiburada_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HI5 //////////////////
    int init_proto_hi5_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HALFLIFE2 //////////////////
    int init_proto_halflife2_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HOMEDEPOT //////////////////
    int init_proto_homedepot_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HOOTSUITE //////////////////
    int init_proto_hootsuite_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HOTMAIL //////////////////
    int init_proto_hotmail_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HTTP //////////////////
    int init_proto_http_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HTTP_CONNECT //////////////////
    int init_proto_http_connect_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HTTP_PROXY //////////////////
    int init_proto_http_proxy_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HTTP_APPLICATION_ACTIVESYNC //////////////////
    int init_proto_http_application_activesync_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HUFFINGTONPOST //////////////////
    int init_proto_huffington_post_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HURRIYET //////////////////
    int init_proto_hurriyet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_I23V5 //////////////////
    int init_proto_i23v5_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IAX //////////////////
    int init_proto_iax_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ICECAST //////////////////
    int init_proto_icecast_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_APPLE_ICLOUD //////////////////
    int init_proto_apple_icloud_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ICMP //////////////////
    int init_proto_icmp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ICMPV6 //////////////////
    int init_proto_icmpv6_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IFENG //////////////////
    int init_proto_ifeng_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IGMP //////////////////
    int init_proto_igmp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IGN //////////////////
    int init_proto_ign_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IKEA //////////////////
    int init_proto_ikea_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IMAP //////////////////
    int init_proto_imap_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IMAPS //////////////////
    int init_proto_imaps_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_INTERNET_MOVIE_DATABASE //////////////////
    int init_proto_internet_movie_database_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IMESH //////////////////
    int init_proto_imesh_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IMESSAGE //////////////////
    int init_proto_imessage_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IMGUR //////////////////
    int init_proto_imgur_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_INCREDIBAR //////////////////
    int init_proto_incredibar_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_INDIATIMES //////////////////
    int init_proto_indiatimes_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_INSTAGRAM //////////////////
    int init_proto_instagram_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IP //////////////////
    int init_proto_ip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IP_IN_IP //////////////////
    int init_proto_ip_in_ip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPP //////////////////
    int init_proto_ipp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPSEC //////////////////
    int init_proto_ipsec_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPV6 //////////////////
    int init_proto_ipv6_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IRC //////////////////
    int init_proto_irc_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IRS //////////////////
    int init_proto_irs_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_APPLE_ITUNES //////////////////
    int init_proto_apple_itunes_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_UNENCRYPED_JABBER //////////////////
    int init_proto_unencryped_jabber_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_JAPANPOST //////////////////
    int init_proto_japanpost_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KAKAO //////////////////
    int init_proto_kakao_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KAT //////////////////
    int init_proto_kat_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KAZAA //////////////////
    int init_proto_kazaa_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KERBEROS //////////////////
    int init_proto_kerberos_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KING //////////////////
    int init_proto_king_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KOHLS //////////////////
    int init_proto_kohls_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KONGREGATE //////////////////
    int init_proto_kongregate_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KONTIKI //////////////////
    int init_proto_kontiki_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_L2TP //////////////////
    int init_proto_l2tp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LASTFM //////////////////
    int init_proto_lastfm_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LDAP //////////////////
    int init_proto_ldap_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LEAGUEOFLEGENDS //////////////////
    int init_proto_leagueoflegends_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LEGACY //////////////////
    int init_proto_legacy_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LETV //////////////////
    int init_proto_letv_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LINKEDIN //////////////////
    int init_proto_linkedin_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVE //////////////////
    int init_proto_live_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVEDOOR //////////////////
    int init_proto_livedoor_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVEHOTMAIL //////////////////
    int init_proto_livehotmail_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVEINTERNET //////////////////
    int init_proto_liveinternet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVEJASMIN //////////////////
    int init_proto_livejasmin_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVEJOURNAL //////////////////
    int init_proto_livejournal_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVESCORE //////////////////
    int init_proto_livescore_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVINGSOCIAL //////////////////
    int init_proto_livingsocial_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LOWES //////////////////
    int init_proto_lowes_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MACYS //////////////////
    int init_proto_macys_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MAIL_RU //////////////////
    int init_proto_mail_ru_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MANET //////////////////
    int init_proto_manet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MANOLITO //////////////////
    int init_proto_manolito_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MAPLESTORY //////////////////
    int init_proto_maplestory_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MATCH //////////////////
    int init_proto_match_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MDNS //////////////////
    int init_proto_mdns_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MEDIAFIRE //////////////////
    int init_proto_mediafire_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MEEBO //////////////////
    int init_proto_meebo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MGCP //////////////////
    int init_proto_mgcp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MICROSOFT //////////////////
    int init_proto_microsoft_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MILLIYET //////////////////
    int init_proto_milliyet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MINECRAFT //////////////////
    int init_proto_minecraft_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MINICLIP //////////////////
    int init_proto_miniclip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MLBASEBALL //////////////////
    int init_proto_mlbaseball_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MMO-CHAMPION //////////////////
    int init_proto_mmo_champion_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MMS //////////////////
    int init_proto_mms_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MOVE //////////////////
    int init_proto_move_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MOZILLA //////////////////
    int init_proto_mozilla_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MPEG //////////////////
    int init_proto_mpeg_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MSN //////////////////
    int init_proto_msn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MSSQL //////////////////
    int init_proto_mssql_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MULTIPLY //////////////////
    int init_proto_multiply_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MYNET //////////////////
    int init_proto_mynet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MYSPACE //////////////////
    int init_proto_myspace_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MYSQL //////////////////
    int init_proto_mysql_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MYWEBSEARCH //////////////////
    int init_proto_mywebsearch_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NBA //////////////////
    int init_proto_nba_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NEOBUX //////////////////
    int init_proto_neobux_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NETBIOS //////////////////
    int init_proto_netbios_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NETFLIX //////////////////
    int init_proto_netflix_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NETFLOW //////////////////
    int init_proto_netflow_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NEWEGG //////////////////
    int init_proto_newegg_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NEWSMAX //////////////////
    int init_proto_newsmax_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NFL //////////////////
    int init_proto_nfl_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NFS //////////////////
    int init_proto_nfs_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NICOVIDEO //////////////////
    int init_proto_nicovideo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NIH //////////////////
    int init_proto_nih_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NORDSTROM //////////////////
    int init_proto_nordstrom_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NTP //////////////////
    int init_proto_ntp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NYTIMES //////////////////
    int init_proto_nytimes_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ODNOKLASSNIKI //////////////////
    int init_proto_odnoklassniki_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_OFF //////////////////
    int init_proto_off_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_OGG //////////////////
    int init_proto_ogg_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ONET //////////////////
    int init_proto_onet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_OPENFT //////////////////
    int init_proto_openft_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ORANGEDONKEY //////////////////
    int init_proto_orangedonkey_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_OSCAR //////////////////
    int init_proto_oscar_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_OSPF //////////////////
    int init_proto_ospf_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_OUTBRAIN //////////////////
    int init_proto_outbrain_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_OVERSTOCK //////////////////
    int init_proto_overstock_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PANDO //////////////////
    int init_proto_pando_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PAYPAL //////////////////
    int init_proto_paypal_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PCANYWHERE //////////////////
    int init_proto_pcanywhere_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PCH //////////////////
    int init_proto_pch_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PCONLINE //////////////////
    int init_proto_pconline_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PHOTOBUCKET //////////////////
    int init_proto_photobucket_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PINTEREST //////////////////
    int init_proto_pinterest_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PLAYSTATION //////////////////
    int init_proto_playstation_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_POGO //////////////////
    int init_proto_pogo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_POP //////////////////
    int init_proto_pop_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_POPS //////////////////
    int init_proto_pops_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_POPO //////////////////
    int init_proto_popo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PORNHUB //////////////////
    int init_proto_pornhub_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_POSTGRES //////////////////
    int init_proto_postgres_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PPLIVE //////////////////
    int init_proto_pplive_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PPP //////////////////
    int init_proto_ppp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PPPoE //////////////////
    int init_proto_pppoe_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PPSTREAM //////////////////
    int init_proto_ppstream_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PPTP //////////////////
    int init_proto_pptp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PREMIERLEAGUE //////////////////
    int init_proto_premierleague_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_QQ //////////////////
    int init_proto_qq_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_QQLIVE //////////////////
    int init_proto_qqlive_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_QUAKE //////////////////
    int init_proto_quake_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_QUICKTIME //////////////////
    int init_proto_quicktime_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_R10 //////////////////
    int init_proto_r10_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RADIUS //////////////////
    int init_proto_radius_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RAKUTEN //////////////////
    int init_proto_rakuten_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RDP //////////////////
    int init_proto_rdp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_REALMEDIA //////////////////
    int init_proto_realmedia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_REDDIT //////////////////
    int init_proto_reddit_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_REDTUBE //////////////////
    int init_proto_redtube_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_REFERENCE //////////////////
    int init_proto_reference_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RENREN //////////////////
    int init_proto_renren_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ROBLOX //////////////////
    int init_proto_roblox_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ROVIO //////////////////
    int init_proto_rovio_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RTP //////////////////
    int init_proto_rtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RTSP //////////////////
    int init_proto_rtsp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SABAHTR //////////////////
    int init_proto_sabahtr_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SAHIBINDEN //////////////////
    int init_proto_sahibinden_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SALESFORCE //////////////////
    int init_proto_salesforce_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SALON //////////////////
    int init_proto_salon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SCTP //////////////////
    int init_proto_sctp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SEARCHNU //////////////////
    int init_proto_searchnu_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SEARCH_RESULTS //////////////////
    int init_proto_search_results_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SEARS //////////////////
    int init_proto_sears_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SECONDLIFE //////////////////
    int init_proto_secondlife_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SECURESERVER //////////////////
    int init_proto_secureserver_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SFLOW //////////////////
    int init_proto_sflow_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SHAZAM //////////////////
    int init_proto_shazam_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SHOUTCAST //////////////////
    int init_proto_shoutcast_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SINA //////////////////
    int init_proto_sina_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SIP //////////////////
    int init_proto_sip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SITEADVISOR //////////////////
    int init_proto_siteadvisor_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SKY //////////////////
    int init_proto_sky_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SKYPE //////////////////
    int init_proto_skype_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SKYROCK //////////////////
    int init_proto_skyrock_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SKYSPORTS //////////////////
    int init_proto_skysports_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SLATE //////////////////
    int init_proto_slate_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SLIDESHARE //////////////////
    int init_proto_slideshare_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SMB //////////////////
    int init_proto_smb_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SMTP //////////////////
    int init_proto_smtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SMTPS //////////////////
    int init_proto_smtps_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SNMP //////////////////
    int init_proto_snmp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOCRATES //////////////////
    int init_proto_socrates_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOFTONIC //////////////////
    int init_proto_softonic_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOGOU //////////////////
    int init_proto_sogou_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOHU //////////////////
    int init_proto_sohu_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOPCAST //////////////////
    int init_proto_sopcast_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOSO //////////////////
    int init_proto_soso_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOULSEEK //////////////////
    int init_proto_soulseek_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOUNDCLOUD //////////////////
    int init_proto_soundcloud_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SOURGEFORGE //////////////////
    int init_proto_sourgeforge_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SPIEGEL //////////////////
    int init_proto_spiegel_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SPORX //////////////////
    int init_proto_sporx_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SPOTIFY //////////////////
    int init_proto_spotify_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SQUIDOO //////////////////
    int init_proto_squidoo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SSDP //////////////////
    int init_proto_ssdp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SSH //////////////////
    int init_proto_ssh_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SSL //////////////////
    int init_proto_ssl_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_STACK_OVERFLOW //////////////////
    int init_proto_stack_overflow_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_STATCOUNTER //////////////////
    int init_proto_statcounter_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_STEALTHNET //////////////////
    int init_proto_stealthnet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_STEAM //////////////////
    int init_proto_steam_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_STUMBLEUPON //////////////////
    int init_proto_stumbleupon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_STUN //////////////////
    int init_proto_stun_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SULEKHA //////////////////
    int init_proto_sulekha_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SYSLOG //////////////////
    int init_proto_syslog_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TAGGED //////////////////
    int init_proto_tagged_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TAOBAO //////////////////
    int init_proto_taobao_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TARGET //////////////////
    int init_proto_target_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TCO //////////////////
    int init_proto_tco_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TCP //////////////////
    int init_proto_tcp_struct();
    // int cleanup_proto_tcp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TDS //////////////////
    int init_proto_tds_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TEAMVIEWER //////////////////
    int init_proto_teamviewer_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TELNET //////////////////
    int init_proto_telnet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TFTP //////////////////
    int init_proto_tftp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_THEMEFOREST //////////////////
    int init_proto_themeforest_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_THE_PIRATE_BAY //////////////////
    int init_proto_the_pirate_bay_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_THUNDER //////////////////
    int init_proto_thunder_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TIANYA //////////////////
    int init_proto_tianya_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TLS //////////////////
    int init_proto_tls_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TMALL //////////////////
    int init_proto_tmall_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TORRENTZ //////////////////
    int init_proto_torrentz_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TRUPHONE //////////////////
    int init_proto_truphone_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TUBE8 //////////////////
    int init_proto_tube8_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TUDOU //////////////////
    int init_proto_tudou_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TUENTI //////////////////
    int init_proto_tuenti_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TUMBLR //////////////////
    int init_proto_tumblr_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TVANTS //////////////////
    int init_proto_tvants_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TVUPLAYER //////////////////
    int init_proto_tvuplayer_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TWITTER //////////////////
    int init_proto_twitter_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_UBI //////////////////
    int init_proto_ubi_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_UCOZ //////////////////
    int init_proto_ucoz_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_UDP //////////////////
    int init_proto_udp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_UDPLITE //////////////////
    int init_proto_udplite_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_UOL //////////////////
    int init_proto_uol_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_USDEPARTMENTOFSTATE //////////////////
    int init_proto_usdepartmentofstate_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_USENET //////////////////
    int init_proto_usenet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_USTREAM //////////////////
    int init_proto_ustream_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HTTP_APPLICATION_VEOHTV //////////////////
    int init_proto_http_application_veohtv_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VIADEO //////////////////
    int init_proto_viadeo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VIBER //////////////////
    int init_proto_viber_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VIMEO //////////////////
    int init_proto_vimeo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VK //////////////////
    int init_proto_vk_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VKONTAKTE //////////////////
    int init_proto_vkontakte_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VNC //////////////////
    int init_proto_vnc_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WALMART //////////////////
    int init_proto_walmart_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WARRIORFORUM //////////////////
    int init_proto_warriorforum_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WAYN //////////////////
    int init_proto_wayn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WEATHER //////////////////
    int init_proto_weather_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WEBEX //////////////////
    int init_proto_webex_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WEEKLYSTANDARD //////////////////
    int init_proto_weeklystandard_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WEIBO //////////////////
    int init_proto_weibo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WELLSFARGO //////////////////
    int init_proto_wellsfargo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WHATSAPP //////////////////
    int init_proto_whatsapp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WIGETMEDIA //////////////////
    int init_proto_wigetmedia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WIKIA //////////////////
    int init_proto_wikia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WIKIMEDIA //////////////////
    int init_proto_wikimedia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WIKIPEDIA //////////////////
    int init_proto_wikipedia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WILLIAMHILL //////////////////
    int init_proto_williamhill_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WINDOWSLIVE //////////////////
    int init_proto_windowslive_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WINDOWSMEDIA //////////////////
    int init_proto_windowsmedia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WINMX //////////////////
    int init_proto_winmx_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WINUPDATE //////////////////
    int init_proto_winupdate_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WORLD_OF_KUNG_FU //////////////////
    int init_proto_world_of_kung_fu_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WORDPRESS_ORG //////////////////
    int init_proto_wordpress_org_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WARCRAFT3 //////////////////
    int init_proto_warcraft3_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WORLDOFWARCRAFT //////////////////
    int init_proto_worldofwarcraft_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WOWHEAD //////////////////
    int init_proto_wowhead_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WWE //////////////////
    int init_proto_wwe_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XBOX //////////////////
    int init_proto_xbox_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XDMCP //////////////////
    int init_proto_xdmcp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XHAMSTER //////////////////
    int init_proto_xhamster_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XING //////////////////
    int init_proto_xing_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XINHUANET //////////////////
    int init_proto_xinhuanet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XNXX //////////////////
    int init_proto_xnxx_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XVIDEOS //////////////////
    int init_proto_xvideos_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YAHOO //////////////////
    int init_proto_yahoo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YAHOOGAMES //////////////////
    int init_proto_yahoogames_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YAHOOMAIL //////////////////
    int init_proto_yahoomail_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YANDEX //////////////////
    int init_proto_yandex_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YELP //////////////////
    int init_proto_yelp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YOUKU //////////////////
    int init_proto_youku_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YOUPORN //////////////////
    int init_proto_youporn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YOUTUBE //////////////////
    int init_proto_youtube_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ZAPPOS //////////////////
    int init_proto_zappos_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ZATTOO //////////////////
    int init_proto_zattoo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ZEDO //////////////////
    int init_proto_zedo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ZOL //////////////////
    int init_proto_zol_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ZYNGA //////////////////
    int init_proto_zynga_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_3PC //////////////////
    int init_proto_3pc_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Any_0hop //////////////////
    int init_proto_any_0hop_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Any_dfs //////////////////
    int init_proto_any_dfs_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Any_hip //////////////////
    int init_proto_any_hip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Any_local //////////////////
    int init_proto_any_local_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Any_pes //////////////////
    int init_proto_any_pes_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ARGUS //////////////////
    int init_proto_argus_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ARIS //////////////////
    int init_proto_aris_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AX_25 //////////////////
    int init_proto_ax_25_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BBN_RCC_MON //////////////////
    int init_proto_bbn_rcc_mon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BNA //////////////////
    int init_proto_bna_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BR_SAT_MON //////////////////
    int init_proto_br_sat_mon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CBT //////////////////
    int init_proto_cbt_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CFTP //////////////////
    int init_proto_cftp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CHAOS //////////////////
    int init_proto_chaos_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Compaq_Peer //////////////////
    int init_proto_compaq_peer_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CPHB //////////////////
    int init_proto_cphb_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CPNX //////////////////
    int init_proto_cpnx_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CRTP //////////////////
    int init_proto_crtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CRUDP //////////////////
    int init_proto_crudp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DCCP //////////////////
    int init_proto_dccp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DCN_MEAS //////////////////
    int init_proto_dcn_meas_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DDP //////////////////
    int init_proto_ddp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DDX //////////////////
    int init_proto_ddx_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DGP //////////////////
    int init_proto_dgp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EIGRP //////////////////
    int init_proto_eigrp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EMCON //////////////////
    int init_proto_emcon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ENCAP //////////////////
    int init_proto_encap_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ETHERIP //////////////////
    int init_proto_etherip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FC //////////////////
    int init_proto_fc_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FIRE //////////////////
    int init_proto_fire_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GGP //////////////////
    int init_proto_ggp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GMTP //////////////////
    int init_proto_gmtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HIP //////////////////
    int init_proto_hip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HMP //////////////////
    int init_proto_hmp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_I_NLSP //////////////////
    int init_proto_i_nlsp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IATP //////////////////
    int init_proto_iatp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IDPR //////////////////
    int init_proto_idpr_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IDPR_CMTP //////////////////
    int init_proto_idpr_cmtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IDRP //////////////////
    int init_proto_idrp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IFMP //////////////////
    int init_proto_ifmp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IGP //////////////////
    int init_proto_igp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IL //////////////////
    int init_proto_il_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPComp //////////////////
    int init_proto_ipcomp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPCV //////////////////
    int init_proto_ipcv_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPLT //////////////////
    int init_proto_iplt_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPPC //////////////////
    int init_proto_ippc_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPTM //////////////////
    int init_proto_iptm_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IPX_in_IP //////////////////
    int init_proto_ipx_in_ip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IRTP //////////////////
    int init_proto_irtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IS_IS //////////////////
    int init_proto_is_is_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ISO_IP //////////////////
    int init_proto_iso_ip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ISO_TP4 //////////////////
    int init_proto_iso_tp4_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_KRYPTOLAN //////////////////
    int init_proto_kryptolan_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LARP //////////////////
    int init_proto_larp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LEAF_1 //////////////////
    int init_proto_leaf_1_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LEAF_2 //////////////////
    int init_proto_leaf_2_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MERIT_INP //////////////////
    int init_proto_merit_inp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MFE_NSP //////////////////
    int init_proto_mfe_nsp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MHRP //////////////////
    int init_proto_mhrp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MICP //////////////////
    int init_proto_micp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MOBILE //////////////////
    int init_proto_mobile_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Mobility_Header //////////////////
    int init_proto_mobility_header_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MPLS_in_IP //////////////////
    int init_proto_mpls_in_ip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MTP //////////////////
    int init_proto_mtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MUX //////////////////
    int init_proto_mux_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NARP //////////////////
    int init_proto_narp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NETBLT //////////////////
    int init_proto_netblt_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NSFNET_IGP //////////////////
    int init_proto_nsfnet_igp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NVP_II //////////////////
    int init_proto_nvp_ii_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PGM //////////////////
    int init_proto_pgm_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PIM //////////////////
    int init_proto_pim_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PIPE //////////////////
    int init_proto_pipe_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PNNI //////////////////
    int init_proto_pnni_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PRM //////////////////
    int init_proto_prm_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PTP //////////////////
    int init_proto_ptp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PUP //////////////////
    int init_proto_pup_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PVP //////////////////
    int init_proto_pvp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_QNX //////////////////
    int init_proto_qnx_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RSVP //////////////////
    int init_proto_rsvp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RSVP_E2E_IGNORE //////////////////
    int init_proto_rsvp_e2e_ignore_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RVD //////////////////
    int init_proto_rvd_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SAT_EXPAK //////////////////
    int init_proto_sat_expak_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SAT_MON //////////////////
    int init_proto_sat_mon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SCC_SP //////////////////
    int init_proto_scc_sp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SCPS //////////////////
    int init_proto_scps_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SDRP //////////////////
    int init_proto_sdrp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SECURE_VMTP //////////////////
    int init_proto_secure_vmtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Shim6 //////////////////
    int init_proto_shim6_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SKIP //////////////////
    int init_proto_skip_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SM //////////////////
    int init_proto_sm_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SMP //////////////////
    int init_proto_smp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SNP //////////////////
    int init_proto_snp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_Sprite_RPC //////////////////
    int init_proto_sprite_rpc_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SPS //////////////////
    int init_proto_sps_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SRP //////////////////
    int init_proto_srp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SSCOPMCE //////////////////
    int init_proto_sscopmce_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ST //////////////////
    int init_proto_st_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_STP //////////////////
    int init_proto_stp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SUN_ND //////////////////
    int init_proto_sun_nd_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SWIPE //////////////////
    int init_proto_swipe_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TCF //////////////////
    int init_proto_tcf_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TLSP //////////////////
    int init_proto_tlsp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TP_pp //////////////////
    int init_proto_tp_pp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TRUNK_1 //////////////////
    int init_proto_trunk_1_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TRUNK_2 //////////////////
    int init_proto_trunk_2_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_UTI //////////////////
    int init_proto_uti_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VINES //////////////////
    int init_proto_vines_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VISA //////////////////
    int init_proto_visa_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VMTP //////////////////
    int init_proto_vmtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VRRP //////////////////
    int init_proto_vrrp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WB_EXPAK //////////////////
    int init_proto_wb_expak_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WB_MON //////////////////
    int init_proto_wb_mon_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WSN //////////////////
    int init_proto_wsn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XNET //////////////////
    int init_proto_xnet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XNS_IDP //////////////////
    int init_proto_xns_idp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_XTP //////////////////
    int init_proto_xtp_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BUZZNET //////////////////
    int init_proto_buzznet_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_COMEDY //////////////////
    int init_proto_comedy_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RAMBLER //////////////////
    int init_proto_rambler_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SMUGMUG //////////////////
    int init_proto_smugmug_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ARCHIEVE //////////////////
    int init_proto_archieve_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CITYNEWS //////////////////
    int init_proto_citynews_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SCIENCESTAGE //////////////////
    int init_proto_sciencestage_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ONEWORLD //////////////////
    int init_proto_oneworld_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DISQUS //////////////////
    int init_proto_disqus_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BLOGCU //////////////////
    int init_proto_blogcu_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EKOLEY //////////////////
    int init_proto_ekoley_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_500PX //////////////////
    int init_proto_500px_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FOTKI //////////////////
    int init_proto_fotki_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FOTOLOG //////////////////
    int init_proto_fotolog_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_JALBUM //////////////////
    int init_proto_jalbum_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LOCKERZ //////////////////
    int init_proto_lockerz_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_PANORAMIO //////////////////
    int init_proto_panoramio_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SNAPFISH //////////////////
    int init_proto_snapfish_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WEBSHOTS //////////////////
    int init_proto_webshots_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MEGA //////////////////
    int init_proto_mega_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VIDOOSH //////////////////
    int init_proto_vidoosh_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AFREECA //////////////////
    int init_proto_afreeca_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WILDSCREEN //////////////////
    int init_proto_wildscreen_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BLOGTV //////////////////
    int init_proto_blogtv_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HULU //////////////////
    int init_proto_hulu_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MEVIO //////////////////
    int init_proto_mevio_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVESTREAM //////////////////
    int init_proto_livestream_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIVELEAK //////////////////
    int init_proto_liveleak_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_DEEZER //////////////////
    int init_proto_deezer_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BLIPTV //////////////////
    int init_proto_bliptv_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BREAK //////////////////
    int init_proto_break_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CITYTV //////////////////
    int init_proto_citytv_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_COMEDYCENTRAL //////////////////
    int init_proto_comedycentral_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_ENGAGEMEDIA //////////////////
    int init_proto_engagemedia_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SCREENJUNKIES //////////////////
    int init_proto_screenjunkies_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RUTUBE //////////////////
    int init_proto_rutube_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SEVENLOAD //////////////////
    int init_proto_sevenload_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MUBI //////////////////
    int init_proto_mubi_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_IZLESENE //////////////////
    int init_proto_izlesene_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VIDEO_HOSTING //////////////////
    int init_proto_video_hosting_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BOX //////////////////
    int init_proto_box_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SKYDRIVE //////////////////
    int init_proto_skydrive_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_7DIGITAL //////////////////
    int init_proto_7digital_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CLOUDFRONT //////////////////
    int init_proto_cloudfront_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_TANGO //////////////////
    int init_proto_tango_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_WECHAT //////////////////
    int init_proto_wechat_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LINE //////////////////
    int init_proto_line_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BLOOMBERG //////////////////
    int init_proto_bloomberg_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MSCDN //////////////////
    int init_proto_mscdn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_AKAMAI //////////////////
    int init_proto_akamai_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_YAHOOMSG //////////////////
    int init_proto_yahoomsg_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BITGRAVITY //////////////////
    int init_proto_bitgravity_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CACHEFLY //////////////////
    int init_proto_cachefly_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CDN77 //////////////////
    int init_proto_cdn77_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CDNETWORKS //////////////////
    int init_proto_cdnetworks_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_CHINACACHE //////////////////
    int init_proto_chinacache_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_COTENDO //////////////////
    int init_proto_cotendo_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_EDGECAST //////////////////
    int init_proto_edgecast_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FASTLY //////////////////
    int init_proto_fastly_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_HIGHWINDS //////////////////
    int init_proto_highwinds_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_INTERNAP //////////////////
    int init_proto_internap_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LEVEL3 //////////////////
    int init_proto_level3_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_LIMELIGHT //////////////////
    int init_proto_limelight_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_MAXCDN //////////////////
    int init_proto_maxcdn_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_NETDNA //////////////////
    int init_proto_netdna_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_VOXEL //////////////////
    int init_proto_voxel_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_RACKSPACE //////////////////
    int init_proto_rackspace_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GAMEFORGE //////////////////
    int init_proto_gameforge_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_METIN2 //////////////////
    int init_proto_metin2_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_OGAME //////////////////
    int init_proto_ogame_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_BATTLEKNIGHT //////////////////
    int init_proto_battleknight_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_4STORY //////////////////
    int init_proto_4story_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_FBMSG //////////////////
    int init_proto_fbmsg_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_GCM //////////////////
    int init_proto_gcm_struct();
    /////////////////////////////////////////////////
    /////////// PLUGIN INIT FOR PROTO_SLL //////////////////
    int init_proto_sll_struct();
    /////////////////////////////////////////////////
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TCPMUX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tcpmux_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_COMPRESSNET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_compressnet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RJE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rje_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ECHO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_echo_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DISCARD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_discard_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SYSTAT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_systat_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DAYTIME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_daytime_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_QOTD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_qotd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MSP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_msp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CHARGEN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_chargen_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FTP_DATA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ftp_data_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NSW_FE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nsw_fe_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MSG_ICP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_msg_icp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MSG_AUTH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_msg_auth_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DSP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dsp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TIME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_time_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RLP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rlp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GRAPHICS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_graphics_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NAME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_name_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NAMESERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nameserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NICNAME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nicname_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MPM_FLAGS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mpm_flags_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MPM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mpm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MPM_SND //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mpm_snd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NI_FTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ni_ftp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AUDITD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_auditd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TACACS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tacacs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RE_MAIL_CK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_re_mail_ck_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XNS_TIME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xns_time_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DOMAIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_domain_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XNS_CH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xns_ch_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ISI_GL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_isi_gl_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XNS_AUTH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xns_auth_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XNS_MAIL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xns_mail_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NI_MAIL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ni_mail_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACAS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_acas_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WHOISPP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_whoispp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WHOIS__ //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_whois___struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_COVIA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_covia_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TACACS_DS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tacacs_ds_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SQL_NET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sql_net_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SQLNET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sqlnet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BOOTPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bootps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BOOTPC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bootpc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GOPHER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_gopher_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETRJS_1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netrjs_1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETRJS_2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netrjs_2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETRJS_3 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netrjs_3_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETRJS_4 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netrjs_4_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DEOS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_deos_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VETTCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vettcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FINGER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_finger_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WWW //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_www_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WWW_HTTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_www_http_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XFER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xfer_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MIT_ML_DEV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mit_ml_dev_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CTF //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ctf_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MFCOBOL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mfcobol_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SU_MIT_TG //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_su_mit_tg_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PORT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_port_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DNSIX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dnsix_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MIT_DOV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mit_dov_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NPP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_npp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OBJCALL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_objcall_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SUPDUP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_supdup_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DIXIE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dixie_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SWIFT_RVF //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_swift_rvf_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TACNEWS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tacnews_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_METAGRAM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_metagram_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HOSTNAME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hostname_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ISO_TSAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iso_tsap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GPPITNP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_gppitnp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACR_NEMA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_acr_nema_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CSO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cso_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CSNET_NS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_csnet_ns_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_3COM_TSMUX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_3com_tsmux_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RTELNET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rtelnet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SNAGAS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_snagas_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_POP2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pop2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_POP3 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pop3_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SUNRPC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sunrpc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MCIDAS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mcidas_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IDENT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ident_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AUTH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_auth_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SFTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sftp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ANSANOTIFY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ansanotify_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UUCP_PATH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_uucp_path_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SQLSERV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sqlserv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NNTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nntp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CFDPTKT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cfdptkt_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ERPC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_erpc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SMAKYNET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_smakynet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ANSATRADER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ansatrader_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LOCUS_MAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_locus_map_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NXEDIT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nxedit_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LOCUS_CON //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_locus_con_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GSS_XLICEN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_gss_xlicen_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PWDGEN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pwdgen_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CISCO_FNA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cisco_fna_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CISCO_TNA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cisco_tna_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CISCO_SYS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cisco_sys_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_STATSRV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_statsrv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_INGRES_NET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ingres_net_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EPMAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_epmap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PROFILE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_profile_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETBIOS_NS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netbios_ns_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETBIOS_DGM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netbios_dgm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETBIOS_SSN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netbios_ssn_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EMFIS_DATA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_emfis_data_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EMFIS_CNTL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_emfis_cntl_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BL_IDM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bl_idm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UMA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_uma_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UAAC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_uaac_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ISO_TP0 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iso_tp0_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_JARGON //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_jargon_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AED_512 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_aed_512_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HEMS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hems_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BFTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bftp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SGMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sgmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETSC_PROD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netsc_prod_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETSC_DEV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netsc_dev_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SQLSRV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sqlsrv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KNET_CMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_knet_cmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PCMAIL_SRV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pcmail_srv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NSS_ROUTING //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nss_routing_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SGMP_TRAPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sgmp_traps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SNMPTRAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_snmptrap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CMIP_MAN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cmip_man_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CMIP_AGENT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cmip_agent_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XNS_COURIER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xns_courier_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_S_NET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_s_net_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NAMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_namp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RSVD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rsvd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SEND //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_send_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PRINT_SRV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_print_srv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MULTIPLEX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_multiplex_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CL_1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cl_1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CL1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cl1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XYPLEX_MUX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xyplex_mux_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MAILQ //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mailq_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VMNET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vmnet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GENRAD_MUX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_genrad_mux_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NEXTSTEP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nextstep_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RIS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ris_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UNIFY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_unify_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AUDIT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_audit_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OCBINDER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ocbinder_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OCSERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ocserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_REMOTE_KIS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_remote_kis_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KIS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_kis_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_aci_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MUMPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mumps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_QFT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_qft_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GACP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_gacp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PROSPERO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_prospero_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OSU_NMS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_osu_nms_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SRMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_srmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DN6_NLM_AUD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dn6_nlm_aud_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DN6_SMM_RED //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dn6_smm_red_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DLS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dls_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DLS_MON //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dls_mon_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SMUX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_smux_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SRC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_src_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AT_RTMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_at_rtmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AT_NBP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_at_nbp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AT_3 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_at_3_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AT_ECHO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_at_echo_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AT_5 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_at_5_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AT_ZIS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_at_zis_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AT_7 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_at_7_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AT_8 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_at_8_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_QMTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_qmtp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_Z39_50 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_z39_50_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_914C_G //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_914c_g_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_914CG //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_914cg_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ANET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_anet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IPX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ipx_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VMPWSCS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vmpwscs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SOFTPC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_softpc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CAILIC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cailic_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DBASE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dbase_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MPP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mpp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UARPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_uarps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IMAP3 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_imap3_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FLN_SPX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_fln_spx_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RSH_SPX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rsh_spx_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CDC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cdc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MASQDIALER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_masqdialer_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DIRECT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_direct_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SUR_MEAS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sur_meas_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_INBUSINESS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_inbusiness_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LINK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_link_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DSP3270 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dsp3270_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SUBNTBCST_TFTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_subntbcst_tftp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BHFHS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bhfhs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_set_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ESRO_GEN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_esro_gen_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OPENPORT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_openport_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NSIIOPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nsiiops_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ARCISDMS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_arcisdms_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HDAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hdap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BGMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bgmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_X_BONE_CTL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_x_bone_ctl_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SST //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sst_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TD_SERVICE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_td_service_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TD_REPLICA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_td_replica_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GIST //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_gist_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PT_TLS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pt_tls_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HTTP_MGMT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_http_mgmt_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PERSONAL_LINK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_personal_link_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CABLEPORT_AX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cableport_ax_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RESCAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rescap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CORERJD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_corerjd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FXP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_fxp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_K_BLOCK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_k_block_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NOVASTORBAKCUP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_novastorbakcup_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ENTRUSTTIME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_entrusttime_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BHMDS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bhmds_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ASIP_WEBADMIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_asip_webadmin_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VSLMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vslmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MAGENTA_LOGIC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_magenta_logic_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OPALIS_ROBOT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_opalis_robot_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DPSI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dpsi_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DECAUTH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_decauth_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ZANNET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_zannet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PKIX_TIMESTAMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pkix_timestamp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PTP_EVENT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ptp_event_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PTP_GENERAL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ptp_general_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PIP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pip_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RTSPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rtsps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RPKI_RTR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rpki_rtr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RPKI_RTR_TLS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rpki_rtr_tls_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TEXAR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_texar_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PDAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pdap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PAWSERV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pawserv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ZSERV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_zserv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FATSERV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_fatserv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CSI_SGWP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_csi_sgwp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MFTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mftp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MATIP_TYPE_A //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_matip_type_a_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MATIP_TYPE_B //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_matip_type_b_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BHOETTY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bhoetty_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DTAG_STE_SB //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dtag_ste_sb_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BHOEDAP4 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bhoedap4_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NDSAUTH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ndsauth_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BH611 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bh611_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DATEX_ASN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_datex_asn_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CLOANTO_NET_1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cloanto_net_1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BHEVENT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bhevent_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SHRINKWRAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_shrinkwrap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NSRMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nsrmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCOI2ODIALOG //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_scoi2odialog_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SEMANTIX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_semantix_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SRSSEND //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_srssend_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RSVP_TUNNEL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rsvp_tunnel_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AURORA_CMGR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_aurora_cmgr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DTK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dtk_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ODMR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_odmr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MORTGAGEWARE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mortgageware_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_QBIKGDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_qbikgdp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RPC2PORTMAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rpc2portmap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CODAAUTH2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_codaauth2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CLEARCASE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_clearcase_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ULISTPROC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ulistproc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LEGENT_1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_legent_1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LEGENT_2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_legent_2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HASSLE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hassle_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NIP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nip_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TNETOS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tnetos_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DSETOS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dsetos_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IS99C //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_is99c_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IS99S //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_is99s_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HP_COLLECTOR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hp_collector_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HP_MANAGED_NODE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hp_managed_node_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HP_ALARM_MGR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hp_alarm_mgr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ARNS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_arns_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IBM_APP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ibm_app_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ASA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_asa_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AURP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_aurp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UNIDATA_LDM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_unidata_ldm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UIS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_uis_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SYNOTICS_RELAY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_synotics_relay_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SYNOTICS_BROKER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_synotics_broker_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_META5 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_meta5_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EMBL_NDT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_embl_ndt_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETWARE_IP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netware_ip_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MPTN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mptn_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ISO_TSAP_C2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iso_tsap_c2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OSB_SD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_osb_sd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ups_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GENIE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_genie_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DECAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_decap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NCED //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nced_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NCLD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ncld_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IMSP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_imsp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TIMBUKTU //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_timbuktu_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PRM_SM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_prm_sm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PRM_NM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_prm_nm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DECLADEBUG //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_decladebug_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RMT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rmt_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SYNOPTICS_TRAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_synoptics_trap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SMSP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_smsp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_INFOSEEK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_infoseek_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BNET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bnet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SILVERPLATTER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_silverplatter_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ONMUX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_onmux_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HYPER_G //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hyper_g_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ARIEL1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ariel1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SMPTE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_smpte_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ARIEL2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ariel2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ARIEL3 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ariel3_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OPC_JOB_START //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_opc_job_start_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OPC_JOB_TRACK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_opc_job_track_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ICAD_EL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_icad_el_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SMARTSDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_smartsdp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SVRLOC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_svrloc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OCS_CMU //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ocs_cmu_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OCS_AMU //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ocs_amu_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UTMPSD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_utmpsd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UTMPCD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_utmpcd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IASD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iasd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NNSP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nnsp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MOBILEIP_AGENT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mobileip_agent_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MOBILIP_MN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mobilip_mn_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DNA_CML //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dna_cml_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_COMSCM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_comscm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DSFGW //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dsfgw_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DASP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dasp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SGCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sgcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DECVMS_SYSMGT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_decvms_sysmgt_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CVC_HOSTD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cvc_hostd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HTTPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_https_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SNPP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_snpp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MICROSOFT_DS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_microsoft_ds_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DDM_RDB //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ddm_rdb_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DDM_DFM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ddm_dfm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DDM_SSL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ddm_ssl_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AS_SERVERMAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_as_servermap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TSERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SFS_SMP_NET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sfs_smp_net_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SFS_CONFIG //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sfs_config_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CREATIVESERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_creativeserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CONTENTSERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_contentserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CREATIVEPARTNR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_creativepartnr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MACON_TCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_macon_tcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MACON_UDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_macon_udp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCOHELP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_scohelp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_APPLEQTC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_appleqtc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AMPR_RCMD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ampr_rcmd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SKRONK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_skronk_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DATASURFSRV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_datasurfsrv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DATASURFSRVSEC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_datasurfsrvsec_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ALPES //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_alpes_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KPASSWD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_kpasswd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_URD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_urd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IGMPV3LITE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_igmpv3lite_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DIGITAL_VRC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_digital_vrc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MYLEX_MAPD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mylex_mapd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PHOTURIS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_photuris_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCX_PROXY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_scx_proxy_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MONDEX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mondex_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LJK_LOGIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ljk_login_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HYBRID_POP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hybrid_pop_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TN_TL_W1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tn_tl_w1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TN_TL_W2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tn_tl_w2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TCPNETHASPSRV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tcpnethaspsrv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TN_TL_FD1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tn_tl_fd1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SS7NS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ss7ns_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SPSC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_spsc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IAFSERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iafserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IAFDBASE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iafdbase_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ph_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BGS_NSI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bgs_nsi_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ULPNET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ulpnet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_INTEGRA_SME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_integra_sme_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_POWERBURST //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_powerburst_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AVIAN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_avian_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SAFT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_saft_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GSS_HTTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_gss_http_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NEST_PROTOCOL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nest_protocol_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MICOM_PFS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_micom_pfs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GO_LOGIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_go_login_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TICF_1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ticf_1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TICF_2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ticf_2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_POV_RAY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pov_ray_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_INTECOURIER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_intecourier_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PIM_RP_DISC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pim_rp_disc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RETROSPECT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_retrospect_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SIAM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_siam_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ISO_ILL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iso_ill_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ISAKMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_isakmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_STMF //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_stmf_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MBAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mbap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_INTRINSA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_intrinsa_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CITADEL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_citadel_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MAILBOX_LM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mailbox_lm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OHIMSRV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ohimsrv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CRS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_crs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XVTTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xvttp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SNARE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_snare_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_fcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PASSGO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_passgo_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EXEC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_exec_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_COMSAT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_comsat_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BIFF //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_biff_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LOGIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_login_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WHO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_who_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SHELL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_shell_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PRINTER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_printer_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VIDEOTEX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_videotex_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TALK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_talk_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NTALK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ntalk_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UTIME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_utime_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EFS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_efs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ROUTER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_router_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RIPNG //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ripng_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ULP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ulp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IBM_DB2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ibm_db2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ncp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TIMED //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_timed_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TEMPO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tempo_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_STX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_stx_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CUSTIX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_custix_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IRC_SERV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_irc_serv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_COURIER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_courier_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CONFERENCE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_conference_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETNEWS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netnews_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETWALL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netwall_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WINDREAM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_windream_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IIOP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iiop_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OPALIS_RDV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_opalis_rdv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NMSP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nmsp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GDOMAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_gdomap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_APERTUS_LDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_apertus_ldp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UUCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_uucp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UUCP_RLOGIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_uucp_rlogin_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_COMMERCE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_commerce_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KLOGIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_klogin_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KSHELL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_kshell_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_APPLEQTCSRVR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_appleqtcsrvr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DHCPV6_CLIENT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dhcpv6_client_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DHCPV6_SERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dhcpv6_server_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AFPOVERTCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_afpovertcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IDFP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_idfp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NEW_RWHO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_new_rwho_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CYBERCASH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cybercash_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DEVSHR_NTS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_devshr_nts_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PIRP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pirp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DSF //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dsf_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_REMOTEFS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_remotefs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OPENVMS_SYSIPC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_openvms_sysipc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SDNSKMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sdnskmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TEEDTAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_teedtap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RMONITOR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rmonitor_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MONITOR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_monitor_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CHSHELL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_chshell_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NNTPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nntps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_9PFS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_9pfs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WHOAMI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_whoami_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_STREETTALK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_streettalk_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BANYAN_RPC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_banyan_rpc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MS_SHUTTLE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ms_shuttle_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MS_ROME //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ms_rome_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_METER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_meter_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SONAR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sonar_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BANYAN_VIP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_banyan_vip_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FTP_AGENT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ftp_agent_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VEMMI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vemmi_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IPCD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ipcd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VNAS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vnas_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IPDD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ipdd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DECBSRV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_decbsrv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SNTP_HEARTBEAT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sntp_heartbeat_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bdp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCC_SECURITY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_scc_security_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PHILIPS_VC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_philips_vc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KEYSERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_keyserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PASSWORD_CHG //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_password_chg_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SUBMISSION //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_submission_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CAL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cal_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EYELINK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_eyelink_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TNS_CML //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tns_cml_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HTTP_ALT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_http_alt_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EUDORA_SET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_eudora_set_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HTTP_RPC_EPMAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_http_rpc_epmap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TPIP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tpip_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CAB_PROTOCOL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cab_protocol_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SMSD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_smsd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PTCNAMESERVICE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ptcnameservice_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCO_WEBSRVRMG3 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sco_websrvrmg3_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_acp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IPCSERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ipcserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SYSLOG_CONN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_syslog_conn_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XMLRPC_BEEP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xmlrpc_beep_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IDXP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_idxp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TUNNEL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tunnel_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SOAP_BEEP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_soap_beep_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_URM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_urm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NQS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nqs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SIFT_UFT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sift_uft_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NPMP_TRAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_npmp_trap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NPMP_LOCAL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_npmp_local_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NPMP_GUI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_npmp_gui_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HMMP_IND //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hmmp_ind_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HMMP_OP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hmmp_op_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SSHELL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sshell_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCO_INETMGR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sco_inetmgr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCO_SYSMGR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sco_sysmgr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCO_DTMGR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sco_dtmgr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DEI_ICDA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dei_icda_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_COMPAQ_EVM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_compaq_evm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SCO_WEBSRVRMGR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sco_websrvrmgr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ESCP_IP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_escp_ip_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_COLLABORATOR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_collaborator_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OOB_WS_HTTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_oob_ws_http_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ASF_RMCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_asf_rmcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CRYPTOADMIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cryptoadmin_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DEC_DLM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dec_dlm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ASIA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_asia_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PASSGO_TIVOLI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_passgo_tivoli_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_QMQP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_qmqp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_3COM_AMP3 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_3com_amp3_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RDA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rda_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BMPP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_bmpp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SERVSTAT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_servstat_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GINAD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ginad_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RLZDBASE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rlzdbase_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LDAPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ldaps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LANSERVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_lanserver_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MCNS_SEC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mcns_sec_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MSDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_msdp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ENTRUST_SPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_entrust_sps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_REPCMD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_repcmd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ESRO_EMSDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_esro_emsdp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SANITY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sanity_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DWR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dwr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PSSC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pssc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ldp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DHCP_FAILOVER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dhcp_failover_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RRP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rrp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CADVIEW_3D //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cadview_3d_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OBEX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_obex_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IEEE_MMS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ieee_mms_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HELLO_PORT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hello_port_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_REPSCMD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_repscmd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AODV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_aodv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TINC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tinc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SPMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_spmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RMC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rmc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TENFOLD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tenfold_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MAC_SRVR_ADMIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mac_srvr_admin_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PFTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pftp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PURENOISE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_purenoise_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OOB_WS_HTTPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_oob_ws_https_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ASF_SECURE_RMCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_asf_secure_rmcp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SUN_DR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_sun_dr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MDQS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mdqs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DOOM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_doom_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DISCLOSE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_disclose_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MECOMM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mecomm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MEREGISTER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_meregister_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VACDSM_SWS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vacdsm_sws_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VACDSM_APP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vacdsm_app_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VPPS_QUA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vpps_qua_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CIMPLEX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cimplex_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_acap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DCTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dctp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VPPS_VIA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vpps_via_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VPP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vpp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GGF_NCP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ggf_ncp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MRM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mrm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ENTRUST_AAAS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_entrust_aaas_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ENTRUST_AAMS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_entrust_aams_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XFR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xfr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CORBA_IIOP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_corba_iiop_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CORBA_IIOP_SSL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_corba_iiop_ssl_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MDC_PORTMAPPER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mdc_portmapper_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HCP_WISMAR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hcp_wismar_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ASIPREGISTRY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_asipregistry_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_REALM_RUSD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_realm_rusd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NMAP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nmap_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VATP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vatp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MSEXCH_ROUTING //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_msexch_routing_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HYPERWAVE_ISP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_hyperwave_isp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CONNENDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_connendp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_HA_CLUSTER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ha_cluster_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IEEE_MMS_SSL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ieee_mms_ssl_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RUSHD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rushd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_UUIDGEN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_uuidgen_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OLSR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_olsr_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACCESSNETWORK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_accessnetwork_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EPP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_epp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_lmp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IRIS_BEEP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iris_beep_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ELCSD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_elcsd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_AGENTX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_agentx_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SILC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_silc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BORLAND_DSJ //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_borland_dsj_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ENTRUST_KMSH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_entrust_kmsh_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ENTRUST_ASH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_entrust_ash_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CISCO_TDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cisco_tdp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TBRPF //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tbrpf_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IRIS_XPC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iris_xpc_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IRIS_XPCS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iris_xpcs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IRIS_LWZ //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iris_lwz_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PANA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pana_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETVIEWDM1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netviewdm1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETVIEWDM2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netviewdm2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETVIEWDM3 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netviewdm3_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETGW //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netgw_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETRCS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netrcs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FLEXLM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_flexlm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FUJITSU_DEV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_fujitsu_dev_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RIS_CM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ris_cm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KERBEROS_ADM //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_kerberos_adm_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RFILE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rfile_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_LOADAV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_loadav_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KERBEROS_IV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_kerberos_iv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PUMP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pump_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_QRH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_qrh_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RRH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rrh_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TELL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_tell_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NLOGIN //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nlogin_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CON //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_con_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ns_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RXE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rxe_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_QUOTAD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_quotad_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CYCLESERV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cycleserv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OMSERV //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_omserv_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WEBSTER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_webster_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PHONEBOOK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_phonebook_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VID //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vid_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CADLOCK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cadlock_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RTIP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rtip_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CYCLESERV2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cycleserv2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SUBMIT //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_submit_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NOTIFY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_notify_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RPASSWD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rpasswd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACMAINT_DBD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_acmaint_dbd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ENTOMB //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_entomb_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACMAINT_TRANSD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_acmaint_transd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WPAGES //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_wpages_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MULTILING_HTTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_multiling_http_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_WPGS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_wpgs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MDBS_DAEMON //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mdbs_daemon_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DEVICE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_device_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MBAP_S //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_mbap_s_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FCP_UDP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_fcp_udp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ITM_MCELL_S //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_itm_mcell_s_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PKIX_3_CA_RA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pkix_3_ca_ra_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETCONF_SSH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netconf_ssh_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETCONF_BEEP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netconf_beep_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETCONFSOAPHTTP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netconfsoaphttp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NETCONFSOAPBEEP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_netconfsoapbeep_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DHCP_FAILOVER2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_dhcp_failover2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GDOI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_gdoi_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_DOMAIN_S //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_domain_s_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ISCSI //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iscsi_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OWAMP_CONTROL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_owamp_control_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TWAMP_CONTROL //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_twamp_control_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_RSYNC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_rsync_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ICLCNET_LOCATE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iclcnet_locate_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ICLCNET_SVINFO //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_iclcnet_svinfo_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_ACCESSBUILDER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_accessbuilder_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CDDBP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cddbp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_OMGINITIALREFS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_omginitialrefs_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SMPNAMERES //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_smpnameres_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IDEAFARM_DOOR //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ideafarm_door_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_IDEAFARM_PANIC //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ideafarm_panic_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_KINK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_kink_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_XACT_BACKUP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_xact_backup_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_APEX_MESH //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_apex_mesh_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_APEX_EDGE //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_apex_edge_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FTPS_DATA //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ftps_data_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_FTPS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_ftps_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_NAS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_nas_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_TELNETS //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_telnets_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_POP3S //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_pop3s_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_VSINET //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_vsinet_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_MAITRD //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_maitrd_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BUSBOY //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_busboy_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PUPARP //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_puparp_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_GARCON //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_garcon_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_APPLIX //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_applix_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_PUPROUTER //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_puprouter_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_CADLOCK2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_cadlock2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_SURF //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_surf_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EXP1 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_exp1_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_EXP2 //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_exp2_struct();
     /////////////////////////////////////////////////
     /////////// PLUGIN INIT FOR PROTO_BLACKJACK //////////////////
     // was generated by MMTCrawler on 8 mar 2016 - @luongnv89
     int init_proto_blackjack_struct();

    ////////// END OF GENERATED CODE ////////////////

#ifdef	__cplusplus
}
#endif

#endif	/* MMT_COMMON_INTERNAL_INCLUDE_H */

