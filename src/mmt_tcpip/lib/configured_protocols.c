#include <stdio.h>
#include <stdlib.h>
#include "mmt_common_internal_include.h"
#include "../include/mmt_tcpip_plugin.h"
#include "../include/mmt_tcpip_protocols.h"

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
    /////////////////START OF GENERATED CODE --- DO NOT MODIFY ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    static const struct { int (*init)(void); const char *name; } proto_init_table[] = {
        { init_proto_163_struct, "proto_163" },
        { init_proto_360_struct, "proto_360" },
        { init_proto_zone_telechargement_struct, "PROTO_ZONE_TELECHARGEMENT" },
        { init_proto_jd_struct, "proto_jd" },
        { init_proto_56_struct, "proto_56" },
        { init_proto_8021q_struct, "proto_8021q" },
        { init_proto_8021ad_struct, "PROTO_8021AD" },
        { init_proto_888poker_struct, "proto_888poker" },
        { init_proto_about_struct, "proto_about" },
        { init_proto_adcash_struct, "proto_adcash" },
        { init_proto_addthis_struct, "proto_addthis" },
        { init_proto_adf_struct, "proto_adf" },
        { init_proto_adobe_struct, "proto_adobe" },
        { init_proto_afp_struct, "proto_afp" },
        { init_proto_ah_struct, "proto_ah" },
        { init_proto_aim_struct, "proto_aim" },
        { init_proto_aimini_struct, "proto_aimini" },
        { init_proto_alibaba_struct, "proto_alibaba" },
        { init_proto_alipay_struct, "proto_alipay" },
        { init_proto_allegro_struct, "proto_allegro" },
        { init_proto_amazon_struct, "proto_amazon" },
        { init_proto_ameblo_struct, "proto_ameblo" },
        { init_proto_ancestry_struct, "proto_ancestry" },
        { init_proto_angrybirds_struct, "proto_angrybirds" },
        { init_proto_answers_struct, "proto_answers" },
        { init_proto_aol_struct, "proto_aol" },
        { init_proto_apple_struct, "proto_apple" },
        { init_proto_applejuice_struct, "proto_applejuice" },
        { init_proto_armagetron_struct, "proto_armagetron" },
        { init_proto_arp_struct, "proto_arp" },
        { init_proto_ask_struct, "proto_ask" },
        { init_proto_avg_struct, "proto_avg" },
        { init_proto_avi_struct, "proto_avi" },
        { init_proto_aweber_struct, "proto_aweber" },
        { init_proto_aws_struct, "proto_aws" },
        { init_proto_babylon_struct, "proto_babylon" },
        { init_proto_badoo_struct, "proto_badoo" },
        { init_proto_baidu_struct, "proto_baidu" },
        { init_proto_bankofamerica_struct, "proto_bankofamerica" },
        { init_proto_barnesandnoble_struct, "proto_barnesandnoble" },
        { init_proto_batman_struct, "proto_batman" },
        { init_proto_battlefield_struct, "proto_battlefield" },
        { init_proto_battlenet_struct, "proto_battlenet" },
        { init_proto_bbb_struct, "proto_bbb" },
        { init_proto_bbc_online_struct, "proto_bbc_online" },
        { init_proto_bestbuy_struct, "proto_bestbuy" },
        { init_proto_betfair_struct, "proto_betfair" },
        { init_proto_bgp_struct, "proto_bgp" },
        { init_proto_biblegateway_struct, "proto_biblegateway" },
        { init_proto_bild_struct, "proto_bild" },
        { init_proto_bing_struct, "proto_bing" },
        { init_proto_bittorrent_struct, "proto_bittorrent" },
        { init_proto_bleacherreport_struct, "proto_bleacherreport" },
        { init_proto_blogfa_struct, "proto_blogfa" },
        { init_proto_blogger_struct, "proto_blogger" },
        { init_proto_blogspot_struct, "proto_blogspot" },
        { init_proto_bodybuilding_struct, "proto_bodybuilding" },
        { init_proto_booking_struct, "proto_booking" },
        { init_proto_cbssports_struct, "proto_cbssports" },
        { init_proto_cnet_struct, "proto_cnet" },
        { init_proto_change_struct, "proto_change" },
        { init_proto_chase_struct, "proto_chase" },
        { init_proto_chess_struct, "proto_chess" },
        { init_proto_chinaz_struct, "proto_chinaz" },
        { init_proto_citrix_struct, "proto_citrix" },
        { init_proto_citrixonline_struct, "proto_citrixonline" },
        { init_proto_clicksor_struct, "proto_clicksor" },
        { init_proto_cnn_struct, "proto_cnn" },
        { init_proto_cnzz_struct, "proto_cnzz" },
        { init_proto_comcast_struct, "proto_comcast" },
        { init_proto_conduit_struct, "proto_conduit" },
        { init_proto_copyscape_struct, "proto_copyscape" },
        { init_proto_correios_struct, "proto_correios" },
        { init_proto_craigslist_struct, "proto_craigslist" },
        { init_proto_crossfire_struct, "proto_crossfire" },
        { init_proto_dailymail_struct, "proto_dailymail" },
        { init_proto_dailymotion_struct, "proto_dailymotion" },
        { init_proto_dcerpc_struct, "proto_dcerpc" },
        { init_proto_direct_download_link_struct, "proto_direct_download_link" },
        { init_proto_deviantart_struct, "proto_deviantart" },
        { init_proto_dhcp_struct, "proto_dhcp" },
        { init_proto_dhcpv6_struct, "proto_dhcpv6" },
        { init_proto_digg_struct, "proto_digg" },
        { init_proto_directconnect_struct, "proto_directconnect" },
        { init_proto_dns_struct, "proto_dns" },
        { init_proto_dofus_struct, "proto_dofus" },
        { init_proto_donanimhaber_struct, "proto_donanimhaber" },
        { init_proto_douban_struct, "proto_douban" },
        { init_proto_doubleclick_struct, "proto_doubleclick" },
        { init_proto_dropbox_struct, "proto_dropbox" },
        { init_proto_ebay_struct, "proto_ebay" },
        { init_proto_edonkey_struct, "proto_edonkey" },
        { init_proto_egp_struct, "proto_egp" },
        { init_proto_ehow_struct, "proto_ehow" },
        { init_proto_eksisozluk_struct, "proto_eksisozluk" },
        { init_proto_electronicsarts_struct, "proto_electronicsarts" },
        { init_proto_esp_struct, "proto_esp" },
        { init_proto_espn_struct, "proto_espn" },
        { init_proto_ethernet_struct, "proto_ethernet" },
        { init_proto_etsy_struct, "proto_etsy" },
        { init_proto_europa_struct, "proto_europa" },
        { init_proto_eurosport_struct, "proto_eurosport" },
        { init_proto_facebook_struct, "proto_facebook" },
        { init_proto_facetime_struct, "proto_facetime" },
        { init_proto_fasttrack_struct, "proto_fasttrack" },
        { init_proto_fc2_struct, "proto_fc2" },
        { init_proto_feidian_struct, "proto_feidian" },
        { init_proto_fiesta_struct, "proto_fiesta" },
        { init_proto_filetopia_struct, "proto_filetopia" },
        { init_proto_fiverr_struct, "proto_fiverr" },
        { init_proto_flash_struct, "proto_flash" },
        { init_proto_flickr_struct, "proto_flickr" },
        { init_proto_florensia_struct, "proto_florensia" },
        { init_proto_foursquare_struct, "proto_foursquare" },
        { init_proto_fox_struct, "proto_fox" },
        { init_proto_free_struct, "proto_free" },
        { init_proto_ftp_struct, "proto_ftp" },
        { init_proto_ndn_struct, "proto_ndn" },
        { init_proto_ndn_http_struct, "proto_ndn_http" },
        { init_proto_gadugadu_struct, "proto_gadugadu" },
        { init_proto_gamefaqs_struct, "proto_gamefaqs" },
        { init_proto_gamespot_struct, "proto_gamespot" },
        { init_proto_gap_struct, "proto_gap" },
        { init_proto_garanti_struct, "proto_garanti" },
        { init_proto_gazetevatan_struct, "proto_gazetevatan" },
        { init_proto_gigapeta_struct, "proto_gigapeta" },
        { init_proto_github_struct, "proto_github" },
        { init_proto_gittigidiyor_struct, "proto_gittigidiyor" },
        { init_proto_globo_struct, "proto_globo" },
        { init_proto_gmail_struct, "proto_gmail" },
        { init_proto_gnutella_struct, "proto_gnutella" },
        { init_proto_google_maps_struct, "proto_google_maps" },
        { init_proto_go_struct, "proto_go" },
        { init_proto_godaddy_struct, "proto_godaddy" },
        { init_proto_goo_struct, "proto_goo" },
        { init_proto_google_struct, "proto_google" },
        { init_proto_google_user_content_struct, "proto_google_user_content" },
        { init_proto_jeuxvideo_struct, "PROTO_JEUXVIDEO" },
        { init_proto_gre_struct, "proto_gre" },
        { init_proto_grooveshark_struct, "proto_grooveshark" },
        { init_proto_groupon_struct, "proto_groupon" },
        { init_proto_gtalk_struct, "proto_gtalk" },
        { init_proto_gtp_struct, "proto_gtp" },
        { init_proto_20minutes_struct, "PROTO_20MINUTES" },
        { init_proto_guardian_struct, "proto_guardian" },
        { init_proto_guildwars_struct, "proto_guildwars" },
        { init_proto_haberturk_struct, "proto_haberturk" },
        { init_proto_hao123_struct, "proto_hao123" },
        { init_proto_hepsiburada_struct, "proto_hepsiburada" },
        { init_proto_hi5_struct, "proto_hi5" },
        { init_proto_halflife2_struct, "proto_halflife2" },
        { init_proto_homedepot_struct, "proto_homedepot" },
        { init_proto_hootsuite_struct, "proto_hootsuite" },
        { init_proto_hotmail_struct, "proto_hotmail" },
        { init_proto_http_struct, "proto_http" },
        { init_proto_reuters_struct, "PROTO_REUTERS" },
        { init_proto_http_proxy_struct, "proto_http_proxy" },
        { init_proto_http_application_activesync_struct, "proto_http_application_activesync" },
        { init_proto_huffingtonpost_struct, "proto_huffingtonpost" },
        { init_proto_hurriyet_struct, "proto_hurriyet" },
        { init_proto_i23v5_struct, "proto_i23v5" },
        { init_proto_iax_struct, "proto_iax" },
        { init_proto_icecast_struct, "proto_icecast" },
        { init_proto_apple_icloud_struct, "proto_apple_icloud" },
        { init_proto_icmp_struct, "proto_icmp" },
        { init_proto_icmpv6_struct, "proto_icmpv6" },
        { init_proto_ifeng_struct, "proto_ifeng" },
        { init_proto_igmp_struct, "proto_igmp" },
        { init_proto_ign_struct, "proto_ign" },
        { init_proto_ikea_struct, "proto_ikea" },
        { init_proto_imap_struct, "proto_imap" },
        { init_proto_imaps_struct, "proto_imaps" },
        { init_proto_imdb_struct, "proto_imdb" },
        { init_proto_imesh_struct, "proto_imesh" },
        { init_proto_aliexpress_struct, "PROTO_ALIEXPRESS" },
        { init_proto_imgur_struct, "proto_imgur" },
        { init_proto_leboncoin_struct, "proto_leboncoin" },
        { init_proto_indiatimes_struct, "proto_indiatimes" },
        { init_proto_instagram_struct, "proto_instagram" },
        { init_proto_ip_struct, "proto_ip" },
        { init_proto_ip_in_ip_struct, "proto_ip_in_ip" },
        { init_proto_ipp_struct, "proto_ipp" },
        { init_proto_ipsec_struct, "proto_ipsec" },
        { init_proto_ipv6_struct, "proto_ipv6" },
        { init_proto_irc_struct, "proto_irc" },
        { init_proto_irs_struct, "proto_irs" },
        { init_proto_apple_itunes_struct, "proto_apple_itunes" },
        { init_proto_unencryped_jabber_struct, "proto_unencryped_jabber" },
        { init_proto_japanpost_struct, "proto_japanpost" },
        { init_proto_kakao_struct, "proto_kakao" },
        { init_proto_kat_struct, "proto_kat" },
        { init_proto_orangefr_struct, "proto_orangefr" },
        { init_proto_kerberos_struct, "proto_kerberos" },
        { init_proto_king_struct, "proto_king" },
        { init_proto_kohls_struct, "proto_kohls" },
        { init_proto_kongregate_struct, "proto_kongregate" },
        { init_proto_kontiki_struct, "proto_kontiki" },
        { init_proto_l2tp_struct, "proto_l2tp" },
        { init_proto_lastfm_struct, "proto_lastfm" },
        { init_proto_ldap_struct, "proto_ldap" },
        { init_proto_leagueoflegends_struct, "proto_leagueoflegends" },
        { init_proto_legacy_struct, "proto_legacy" },
        { init_proto_letv_struct, "proto_letv" },
        { init_proto_linkedin_struct, "proto_linkedin" },
        { init_proto_live_struct, "proto_live" },
        { init_proto_livedoor_struct, "proto_livedoor" },
        { init_proto_livehotmail_struct, "proto_livehotmail" },
        { init_proto_liveinternet_struct, "proto_liveinternet" },
        { init_proto_livejasmin_struct, "proto_livejasmin" },
        { init_proto_livejournal_struct, "proto_livejournal" },
        { init_proto_livescore_struct, "proto_livescore" },
        { init_proto_livingsocial_struct, "proto_livingsocial" },
        { init_proto_lowes_struct, "proto_lowes" },
        { init_proto_macys_struct, "proto_macys" },
        { init_proto_mail_ru_struct, "proto_mail_ru" },
        { init_proto_fnac_struct, "PROTO_FNAC" },
        { init_proto_manolito_struct, "proto_manolito" },
        { init_proto_maplestory_struct, "proto_maplestory" },
        { init_proto_match_struct, "proto_match" },
        { init_proto_mdns_struct, "proto_mdns" },
        { init_proto_mediafire_struct, "proto_mediafire" },
        { init_proto_meebo_struct, "proto_meebo" },
        { init_proto_mgcp_struct, "proto_mgcp" },
        { init_proto_microsoft_struct, "proto_microsoft" },
        { init_proto_milliyet_struct, "proto_milliyet" },
        { init_proto_minecraft_struct, "proto_minecraft" },
        { init_proto_miniclip_struct, "proto_miniclip" },
        { init_proto_mlbaseball_struct, "proto_mlbaseball" },
        { init_proto_mmo_champion_struct, "proto_mmo-champion" },
        { init_proto_mms_struct, "proto_mms" },
        { init_proto_move_struct, "proto_move" },
        { init_proto_mozilla_struct, "proto_mozilla" },
        { init_proto_mpeg_struct, "proto_mpeg" },
        { init_proto_msn_struct, "proto_msn" },
        { init_proto_mssql_struct, "proto_mssql" },
        { init_proto_multiply_struct, "proto_multiply" },
        { init_proto_mynet_struct, "proto_mynet" },
        { init_proto_myspace_struct, "proto_myspace" },
        { init_proto_mysql_struct, "proto_mysql" },
        { init_proto_mywebsearch_struct, "proto_mywebsearch" },
        { init_proto_nba_struct, "proto_nba" },
        { init_proto_neobux_struct, "proto_neobux" },
        { init_proto_netbios_struct, "proto_netbios" },
        { init_proto_mqtt_struct, "proto_mqtt" },
        { init_proto_netflix_struct, "proto_netflix" },
        { init_proto_netflow_struct, "proto_netflow" },
        { init_proto_newegg_struct, "proto_newegg" },
        { init_proto_newsmax_struct, "proto_newsmax" },
        { init_proto_nfl_struct, "proto_nfl" },
        { init_proto_nfs_struct, "proto_nfs" },
        { init_proto_nicovideo_struct, "proto_nicovideo" },
        { init_proto_nih_struct, "proto_nih" },
        { init_proto_nordstrom_struct, "proto_nordstrom" },
        { init_proto_ntp_struct, "proto_ntp" },
        { init_proto_nytimes_struct, "proto_nytimes" },
        { init_proto_odnoklassniki_struct, "proto_odnoklassniki" },
        { init_proto_off_struct, "proto_off" },
        { init_proto_ogg_struct, "proto_ogg" },
        { init_proto_onet_struct, "proto_onet" },
        { init_proto_openft_struct, "proto_openft" },
        { init_proto_orangedonkey_struct, "proto_orangedonkey" },
        { init_proto_oscar_struct, "proto_oscar" },
        { init_proto_ospf_struct, "proto_ospf" },
        { init_proto_outbrain_struct, "proto_outbrain" },
        { init_proto_overstock_struct, "proto_overstock" },
        { init_proto_pando_struct, "proto_pando" },
        { init_proto_paypal_struct, "proto_paypal" },
        { init_proto_pcanywhere_struct, "proto_pcanywhere" },
        { init_proto_pch_struct, "proto_pch" },
        { init_proto_pconline_struct, "proto_pconline" },
        { init_proto_photobucket_struct, "proto_photobucket" },
        { init_proto_pinterest_struct, "proto_pinterest" },
        { init_proto_playstation_struct, "proto_playstation" },
        { init_proto_pogo_struct, "proto_pogo" },
        { init_proto_pop_struct, "proto_pop" },
        { init_proto_pops_struct, "proto_pops" },
        { init_proto_popo_struct, "proto_popo" },
        { init_proto_pornhub_struct, "proto_pornhub" },
        { init_proto_postgres_struct, "proto_postgres" },
        { init_proto_pplive_struct, "proto_pplive" },
        { init_proto_ppp_struct, "proto_ppp" },
        { init_proto_pppoe_struct, "proto_pppoe" },
        { init_proto_ppstream_struct, "proto_ppstream" },
        { init_proto_pptp_struct, "proto_pptp" },
        { init_proto_premierleague_struct, "proto_premierleague" },
        { init_proto_qq_struct, "proto_qq" },
        { init_proto_qqlive_struct, "proto_qqlive" },
        { init_proto_quake_struct, "proto_quake" },
        { init_proto_forbes_struct, "PROTO_FORBES" },
        { init_proto_r10_struct, "proto_r10" },
        { init_proto_radius_struct, "proto_radius" },
        { init_proto_rakuten_struct, "proto_rakuten" },
        { init_proto_rdp_struct, "proto_rdp" },
        { init_proto_realmedia_struct, "proto_realmedia" },
        { init_proto_reddit_struct, "proto_reddit" },
        { init_proto_redtube_struct, "proto_redtube" },
        { init_proto_reference_struct, "proto_reference" },
        { init_proto_renren_struct, "proto_renren" },
        { init_proto_roblox_struct, "proto_roblox" },
        { init_proto_rovio_struct, "proto_rovio" },
        { init_proto_rtp_struct, "proto_rtp" },
        { init_proto_rtsp_struct, "proto_rtsp" },
        { init_proto_sabah_struct, "proto_sabah" },
        { init_proto_sahibinden_struct, "proto_sahibinden" },
        { init_proto_salesforce_struct, "proto_salesforce" },
        { init_proto_salon_struct, "proto_salon" },
        { init_proto_sctp_struct, "proto_sctp" },
        { init_proto_searchnu_struct, "proto_searchnu" },
        { init_proto_search_results_struct, "proto_search_results" },
        { init_proto_sears_struct, "proto_sears" },
        { init_proto_secondlife_struct, "proto_secondlife" },
        { init_proto_secureserver_struct, "proto_secureserver" },
        { init_proto_sflow_struct, "proto_sflow" },
        { init_proto_shazam_struct, "proto_shazam" },
        { init_proto_shoutcast_struct, "proto_shoutcast" },
        { init_proto_sina_struct, "proto_sina" },
        { init_proto_sip_struct, "proto_sip" },
        { init_proto_siteadvisor_struct, "proto_siteadvisor" },
        { init_proto_sky_struct, "proto_sky" },
        { init_proto_skype_struct, "proto_skype" },
        { init_proto_skyrock_struct, "proto_skyrock" },
        { init_proto_skysports_struct, "proto_skysports" },
        { init_proto_slate_struct, "proto_slate" },
        { init_proto_slideshare_struct, "proto_slideshare" },
        { init_proto_smb_struct, "proto_smb" },
        { init_proto_smtp_struct, "proto_smtp" },
        { init_proto_smtps_struct, "proto_smtps" },
        { init_proto_snmp_struct, "proto_snmp" },
        { init_proto_socrates_struct, "proto_socrates" },
        { init_proto_softonic_struct, "proto_softonic" },
        { init_proto_sogou_struct, "proto_sogou" },
        { init_proto_sohu_struct, "proto_sohu" },
        { init_proto_sopcast_struct, "proto_sopcast" },
        { init_proto_soso_struct, "proto_soso" },
        { init_proto_soulseek_struct, "proto_soulseek" },
        { init_proto_soundcloud_struct, "proto_soundcloud" },
        { init_proto_sourceforge_struct, "proto_sourceforge" },
        { init_proto_spiegel_struct, "proto_spiegel" },
        { init_proto_sporx_struct, "proto_sporx" },
        { init_proto_spotify_struct, "proto_spotify" },
        { init_proto_squidoo_struct, "proto_squidoo" },
        { init_proto_ssdp_struct, "proto_ssdp" },
        { init_proto_ssh_struct, "proto_ssh" },
        { init_proto_ssl_struct, "proto_ssl" },
        { init_proto_stack_overflow_struct, "proto_stack_overflow" },
        { init_proto_statcounter_struct, "proto_statcounter" },
        { init_proto_stealthnet_struct, "proto_stealthnet" },
        { init_proto_steam_struct, "proto_steam" },
        { init_proto_stumbleupon_struct, "proto_stumbleupon" },
        { init_proto_stun_struct, "proto_stun" },
        { init_proto_sulekha_struct, "proto_sulekha" },
        { init_proto_syslog_struct, "proto_syslog" },
        { init_proto_tagged_struct, "proto_tagged" },
        { init_proto_taobao_struct, "proto_taobao" },
        { init_proto_target_struct, "proto_target" },
        { init_proto_tco_struct, "proto_tco" },
        { init_proto_tcp_struct, "proto_tcp" },
        { init_proto_tds_struct, "proto_tds" },
        { init_proto_teamviewer_struct, "proto_teamviewer" },
        { init_proto_telnet_struct, "proto_telnet" },
        { init_proto_tftp_struct, "proto_tftp" },
        { init_proto_themeforest_struct, "proto_themeforest" },
        { init_proto_the_pirate_bay_struct, "proto_the_pirate_bay" },
        { init_proto_thunder_struct, "proto_thunder" },
        { init_proto_tianya_struct, "proto_tianya" },
        { init_proto_cdiscount_struct, "PROTO_CDISCOUNT" },
        { init_proto_tmall_struct, "proto_tmall" },
        { init_proto_torrentz_struct, "proto_torrentz" },
        { init_proto_truphone_struct, "proto_truphone" },
        { init_proto_tube8_struct, "proto_tube8" },
        { init_proto_tudou_struct, "proto_tudou" },
        { init_proto_tuenti_struct, "proto_tuenti" },
        { init_proto_tumblr_struct, "proto_tumblr" },
        { init_proto_tvants_struct, "proto_tvants" },
        { init_proto_tvuplayer_struct, "proto_tvuplayer" },
        { init_proto_twitter_struct, "proto_twitter" },
        { init_proto_ubi_struct, "proto_ubi" },
        { init_proto_ucoz_struct, "proto_ucoz" },
        { init_proto_udp_struct, "proto_udp" },
        { init_proto_udplite_struct, "proto_udplite" },
        { init_proto_uol_struct, "proto_uol" },
        { init_proto_usdepartmentofstate_struct, "proto_usdepartmentofstate" },
        { init_proto_usenet_struct, "proto_usenet" },
        { init_proto_ustream_struct, "proto_ustream" },
        { init_proto_http_application_veohtv_struct, "proto_http_application_veohtv" },
        { init_proto_viadeo_struct, "proto_viadeo" },
        { init_proto_viber_struct, "proto_viber" },
        { init_proto_vimeo_struct, "proto_vimeo" },
        { init_proto_vk_struct, "proto_vk" },
        { init_proto_vkontakte_struct, "proto_vkontakte" },
        { init_proto_vnc_struct, "proto_vnc" },
        { init_proto_walmart_struct, "proto_walmart" },
        { init_proto_warriorforum_struct, "proto_warriorforum" },
        { init_proto_wayn_struct, "proto_wayn" },
        { init_proto_weather_struct, "proto_weather" },
        { init_proto_webex_struct, "proto_webex" },
        { init_proto_weeklystandard_struct, "proto_weeklystandard" },
        { init_proto_weibo_struct, "proto_weibo" },
        { init_proto_wellsfargo_struct, "proto_wellsfargo" },
        { init_proto_whatsapp_struct, "proto_whatsapp" },
        { init_proto_wigetmedia_struct, "proto_wigetmedia" },
        { init_proto_wikia_struct, "proto_wikia" },
        { init_proto_wikimedia_struct, "proto_wikimedia" },
        { init_proto_wikipedia_struct, "proto_wikipedia" },
        { init_proto_williamhill_struct, "proto_williamhill" },
        { init_proto_windowslive_struct, "proto_windowslive" },
        { init_proto_windowsmedia_struct, "proto_windowsmedia" },
        { init_proto_winmx_struct, "proto_winmx" },
        { init_proto_winupdate_struct, "proto_winupdate" },
        { init_proto_world_of_kung_fu_struct, "proto_world_of_kung_fu" },
        { init_proto_wordpress_org_struct, "proto_wordpress_org" },
        { init_proto_warcraft3_struct, "proto_warcraft3" },
        { init_proto_worldofwarcraft_struct, "proto_worldofwarcraft" },
        { init_proto_wowhead_struct, "proto_wowhead" },
        { init_proto_wwe_struct, "proto_wwe" },
        { init_proto_xbox_struct, "proto_xbox" },
        { init_proto_xdmcp_struct, "proto_xdmcp" },
        { init_proto_xhamster_struct, "proto_xhamster" },
        { init_proto_xing_struct, "proto_xing" },
        { init_proto_xinhuanet_struct, "proto_xinhuanet" },
        { init_proto_xnxx_struct, "proto_xnxx" },
        { init_proto_xvideos_struct, "proto_xvideos" },
        { init_proto_yahoo_struct, "proto_yahoo" },
        { init_proto_allocine_struct, "PROTO_ALLOCINE" },
        { init_proto_yahoomail_struct, "proto_yahoomail" },
        { init_proto_yandex_struct, "proto_yandex" },
        { init_proto_yelp_struct, "proto_yelp" },
        { init_proto_youku_struct, "proto_youku" },
        { init_proto_youporn_struct, "proto_youporn" },
        { init_proto_youtube_struct, "proto_youtube" },
        { init_proto_zappos_struct, "proto_zappos" },
        { init_proto_zattoo_struct, "proto_zattoo" },
        { init_proto_zedo_struct, "proto_zedo" },
        { init_proto_zol_struct, "proto_zol" },
        { init_proto_zynga_struct, "proto_zynga" },
        { init_proto_3pc_struct, "PROTO_3pc" },
        { init_proto_any_0hop_struct, "PROTO_any_0hop" },
        { init_proto_any_dfs_struct, "PROTO_any_dfs" },
        { init_proto_any_hip_struct, "PROTO_any_hip" },
        { init_proto_any_local_struct, "PROTO_any_local" },
        { init_proto_any_pes_struct, "PROTO_any_pes" },
        { init_proto_argus_struct, "PROTO_argus" },
        { init_proto_aris_struct, "PROTO_aris" },
        { init_proto_ax_25_struct, "PROTO_ax_25" },
        { init_proto_bbn_rcc_mon_struct, "PROTO_bbn_rcc_mon" },
        { init_proto_bna_struct, "PROTO_bna" },
        { init_proto_br_sat_mon_struct, "PROTO_br_sat_mon" },
        { init_proto_cbt_struct, "PROTO_cbt" },
        { init_proto_cftp_struct, "PROTO_cftp" },
        { init_proto_chaos_struct, "PROTO_chaos" },
        { init_proto_compaq_peer_struct, "PROTO_compaq_peer" },
        { init_proto_cphb_struct, "PROTO_cphb" },
        { init_proto_cpnx_struct, "PROTO_cpnx" },
        { init_proto_crtp_struct, "PROTO_crtp" },
        { init_proto_crudp_struct, "PROTO_crudp" },
        { init_proto_dccp_struct, "PROTO_dccp" },
        { init_proto_dcn_meas_struct, "PROTO_dcn_meas" },
        { init_proto_ddp_struct, "PROTO_ddp" },
        { init_proto_ddx_struct, "PROTO_ddx" },
        { init_proto_dgp_struct, "PROTO_dgp" },
        { init_proto_eigrp_struct, "PROTO_eigrp" },
        { init_proto_emcon_struct, "PROTO_emcon" },
        { init_proto_encap_struct, "PROTO_encap" },
        { init_proto_etherip_struct, "PROTO_etherip" },
        { init_proto_fc_struct, "PROTO_fc" },
        { init_proto_fire_struct, "PROTO_fire" },
        { init_proto_ggp_struct, "PROTO_ggp" },
        { init_proto_gmtp_struct, "PROTO_gmtp" },
        { init_proto_hip_struct, "PROTO_hip" },
        { init_proto_hmp_struct, "PROTO_hmp" },
        { init_proto_i_nlsp_struct, "PROTO_i_nlsp" },
        { init_proto_iatp_struct, "PROTO_iatp" },
        { init_proto_idpr_struct, "PROTO_idpr" },
        { init_proto_idpr_cmtp_struct, "PROTO_idpr_cmtp" },
        { init_proto_idrp_struct, "PROTO_idrp" },
        { init_proto_ifmp_struct, "PROTO_ifmp" },
        { init_proto_igp_struct, "PROTO_igp" },
        { init_proto_il_struct, "PROTO_il" },
        { init_proto_ipcomp_struct, "PROTO_ipcomp" },
        { init_proto_ipcv_struct, "PROTO_ipcv" },
        { init_proto_iplt_struct, "PROTO_iplt" },
        { init_proto_ippc_struct, "PROTO_ippc" },
        { init_proto_iptm_struct, "PROTO_iptm" },
        { init_proto_ipx_in_ip_struct, "PROTO_ipx_in_ip" },
        { init_proto_irtp_struct, "PROTO_irtp" },
        { init_proto_is_is_struct, "PROTO_is_is" },
        { init_proto_iso_ip_struct, "PROTO_iso_ip" },
        { init_proto_iso_tp4_struct, "PROTO_iso_tp4" },
        { init_proto_kryptolan_struct, "PROTO_kryptolan" },
        { init_proto_larp_struct, "PROTO_larp" },
        { init_proto_leaf_1_struct, "PROTO_leaf_1" },
        { init_proto_leaf_2_struct, "PROTO_leaf_2" },
        { init_proto_merit_inp_struct, "PROTO_merit_inp" },
        { init_proto_mfe_nsp_struct, "PROTO_mfe_nsp" },
        { init_proto_mhrp_struct, "PROTO_mhrp" },
        { init_proto_micp_struct, "PROTO_micp" },
        { init_proto_mobile_struct, "PROTO_mobile" },
        { init_proto_mobility_header_struct, "PROTO_mobility_header" },
        { init_proto_mpls_in_ip_struct, "PROTO_mpls_in_ip" },
        { init_proto_mtp_struct, "PROTO_mtp" },
        { init_proto_mux_struct, "PROTO_mux" },
        { init_proto_narp_struct, "PROTO_narp" },
        { init_proto_netblt_struct, "PROTO_netblt" },
        { init_proto_nsfnet_igp_struct, "PROTO_nsfnet_igp" },
        { init_proto_nvp_ii_struct, "PROTO_nvp_ii" },
        { init_proto_pgm_struct, "PROTO_pgm" },
        { init_proto_pim_struct, "PROTO_pim" },
        { init_proto_pipe_struct, "PROTO_pipe" },
        { init_proto_pnni_struct, "PROTO_pnni" },
        { init_proto_prm_struct, "PROTO_prm" },
        { init_proto_ptp_struct, "PROTO_ptp" },
        { init_proto_pup_struct, "PROTO_pup" },
        { init_proto_pvp_struct, "PROTO_pvp" },
        { init_proto_qnx_struct, "PROTO_qnx" },
        { init_proto_rsvp_struct, "PROTO_rsvp" },
        { init_proto_rsvp_e2e_ignore_struct, "PROTO_rsvp_e2e_ignore" },
        { init_proto_rvd_struct, "PROTO_rvd" },
        { init_proto_sat_expak_struct, "PROTO_sat_expak" },
        { init_proto_sat_mon_struct, "PROTO_sat_mon" },
        { init_proto_scc_sp_struct, "PROTO_scc_sp" },
        { init_proto_scps_struct, "PROTO_scps" },
        { init_proto_sdrp_struct, "PROTO_sdrp" },
        { init_proto_secure_vmtp_struct, "PROTO_secure_vmtp" },
        { init_proto_shim6_struct, "PROTO_shim6" },
        { init_proto_skip_struct, "PROTO_skip" },
        { init_proto_sm_struct, "PROTO_sm" },
        { init_proto_smp_struct, "PROTO_smp" },
        { init_proto_snp_struct, "PROTO_snp" },
        { init_proto_sprite_rpc_struct, "PROTO_sprite_rpc" },
        { init_proto_sps_struct, "PROTO_sps" },
        { init_proto_srp_struct, "PROTO_srp" },
        { init_proto_sscopmce_struct, "PROTO_sscopmce" },
        { init_proto_st_struct, "PROTO_st" },
        { init_proto_stp_struct, "PROTO_stp" },
        { init_proto_sun_nd_struct, "PROTO_sun_nd" },
        { init_proto_swipe_struct, "PROTO_swipe" },
        { init_proto_tcf_struct, "PROTO_tcf" },
        { init_proto_tlsp_struct, "PROTO_tlsp" },
        { init_proto_tp_pp_struct, "PROTO_tp_pp" },
        { init_proto_trunk_1_struct, "PROTO_trunk_1" },
        { init_proto_trunk_2_struct, "PROTO_trunk_2" },
        { init_proto_uti_struct, "PROTO_uti" },
        { init_proto_vines_struct, "PROTO_vines" },
        { init_proto_visa_struct, "PROTO_visa" },
        { init_proto_vmtp_struct, "PROTO_vmtp" },
        { init_proto_vrrp_struct, "PROTO_vrrp" },
        { init_proto_wb_expak_struct, "PROTO_wb_expak" },
        { init_proto_wb_mon_struct, "PROTO_wb_mon" },
        { init_proto_wsn_struct, "PROTO_wsn" },
        { init_proto_xnet_struct, "PROTO_xnet" },
        { init_proto_xns_idp_struct, "PROTO_xns_idp" },
        { init_proto_xtp_struct, "PROTO_xtp" },
        { init_proto_buzznet_struct, "PROTO_buzznet" },
        { init_proto_comedy_struct, "PROTO_comedy" },
        { init_proto_rambler_struct, "PROTO_rambler" },
        { init_proto_smugmug_struct, "PROTO_smugmug" },
        { init_proto_archieve_struct, "PROTO_archieve" },
        { init_proto_citynews_struct, "PROTO_citynews" },
        { init_proto_sciencestage_struct, "PROTO_sciencestage" },
        { init_proto_oneworld_struct, "PROTO_oneworld" },
        { init_proto_disqus_struct, "PROTO_disqus" },
        { init_proto_blogcu_struct, "PROTO_blogcu" },
        { init_proto_ekolay_struct, "PROTO_ekolay" },
        { init_proto_500px_struct, "PROTO_500px" },
        { init_proto_fotki_struct, "PROTO_fotki" },
        { init_proto_fotolog_struct, "PROTO_fotolog" },
        { init_proto_jalbum_struct, "PROTO_jalbum" },
        { init_proto_lemonde_struct, "PROTO_LEMONDE" },
        { init_proto_panoramio_struct, "PROTO_panoramio" },
        { init_proto_snapfish_struct, "PROTO_snapfish" },
        { init_proto_webshots_struct, "PROTO_webshots" },
        { init_proto_mega_struct, "PROTO_mega" },
        { init_proto_vidoosh_struct, "PROTO_vidoosh" },
        { init_proto_afreeca_struct, "PROTO_afreeca" },
        { init_proto_wildscreen_struct, "PROTO_wildscreen" },
        { init_proto_blogtv_struct, "PROTO_blogtv" },
        { init_proto_hulu_struct, "PROTO_hulu" },
        { init_proto_mevio_struct, "PROTO_mevio" },
        { init_proto_livestream_struct, "PROTO_livestream" },
        { init_proto_liveleak_struct, "PROTO_liveleak" },
        { init_proto_deezer_struct, "PROTO_deezer" },
        { init_proto_bliptv_struct, "PROTO_bliptv" },
        { init_proto_break_struct, "PROTO_break" },
        { init_proto_citytv_struct, "PROTO_citytv" },
        { init_proto_comedycentral_struct, "PROTO_comedycentral" },
        { init_proto_engagemedia_struct, "PROTO_engagemedia" },
        { init_proto_screenjunkies_struct, "PROTO_screenjunkies" },
        { init_proto_rutube_struct, "PROTO_rutube" },
        { init_proto_sevenload_struct, "PROTO_sevenload" },
        { init_proto_mubi_struct, "PROTO_mubi" },
        { init_proto_izlesene_struct, "PROTO_izlesene" },
        { init_proto_video_hosting_struct, "PROTO_video_hosting" },
        { init_proto_box_struct, "PROTO_box" },
        { init_proto_skydrive_struct, "PROTO_skydrive" },
        { init_proto_7digital_struct, "PROTO_7digital" },
        { init_proto_cloudfront_struct, "PROTO_cloudfront" },
        { init_proto_tango_struct, "PROTO_tango" },
        { init_proto_wechat_struct, "PROTO_wechat" },
        { init_proto_line_struct, "PROTO_line" },
        { init_proto_bloomberg_struct, "PROTO_bloomberg" },
        { init_proto_lefigaro_struct, "PROTO_LEFIGARO" },
        { init_proto_akamai_struct, "PROTO_akamai" },
        { init_proto_yahoomsg_struct, "PROTO_yahoomsg" },
        { init_proto_bitgravity_struct, "PROTO_bitgravity" },
        { init_proto_cachefly_struct, "PROTO_cachefly" },
        { init_proto_cdn77_struct, "PROTO_cdn77" },
        { init_proto_cdnetworks_struct, "PROTO_cdnetworks" },
        { init_proto_chinacache_struct, "PROTO_chinacache" },
        { init_proto_francetvinfo_struct, "PROTO_FRANCETVINFO" },
        { init_proto_edgecast_struct, "PROTO_edgecast" },
        { init_proto_fastly_struct, "PROTO_fastly" },
        { init_proto_highwinds_struct, "PROTO_highwinds" },
        { init_proto_internap_struct, "PROTO_internap" },
        { init_proto_level3_struct, "PROTO_level3" },
        { init_proto_limelight_struct, "PROTO_limelight" },
        { init_proto_maxcdn_struct, "PROTO_maxcdn" },
        { init_proto_netdna_struct, "PROTO_netdna" },
        { init_proto_stackpath_struct, "PROTO_STACKPATH" },
        { init_proto_rackspace_struct, "PROTO_rackspace" },
        { init_proto_gameforge_struct, "PROTO_gameforge" },
        { init_proto_metin2_struct, "PROTO_metin2" },
        { init_proto_ogame_struct, "PROTO_ogame" },
        { init_proto_battleknight_struct, "PROTO_battleknight" },
        { init_proto_4story_struct, "PROTO_4story" },
        { init_proto_fbmsg_struct, "PROTO_fbmsg" },
        { init_proto_twitch_struct, "PROTO_TWITCH" },
        { init_proto_sll_struct, "PROTO_SLL" },
        { init_proto_quic_struct, "proto_quic" },
        { init_proto_oracle_struct, "proto_oracle" },
        { init_proto_redis_struct, "proto_redis" },
        { init_proto_vmware_struct, "proto_vmware" },
        { init_proto_llmnr_struct, "proto_llmnr" },
        { init_proto_eclipse_tcf_struct, "PROTO_ECLIPSE_TCF" },
        { init_proto_loopback_struct, "PROTO_LOOPBACK" },
        { init_proto_ctp_struct, "PROTO_CTP" },
        { init_proto_tpkt_struct, "PROTO_tpkt" },
        { init_proto_cotp_struct, "PROTO_cotp" },
        { init_proto_s7comm_struct, "PROTO_s7comm" },
        { init_proto_llc_struct, "PROTO_LLC" },
        { init_proto_xid_struct, "PROTO_XID" },
        { init_proto_cdp_struct, "PROTO_CDP" },
        { init_proto_dtp_struct, "PROTO_DTP" },
        { init_proto_inband_network_telemetry_struct, "PROTO_INT_REPORT" },
        { init_proto_int_struct, "PROTO_INT" },
        { init_proto_quic_ietf_struct, "PROTO_QUIC_IETF" },
        { init_proto_cloudflare_struct, "PROTO_CLOUDFLARE" },
        { init_proto_azure_struct, "PROTO_AZURE" },
        { init_http2_proto_struct, "PROTO_HTTP2" },
    };
    for (size_t i = 0; i < sizeof(proto_init_table)/sizeof(proto_init_table[0]); i++) {
        if (!proto_init_table[i].init()) {
            fprintf(stderr, "Error initializing protocol %s\n Exiting\n", proto_init_table[i].name);
            return 0;
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////END OF GENERATED CODE ////////////////////////////
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
     register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_http2, 9);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_http, 20);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ssl, 20);

    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dns, 30);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_imap, 30);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_smtp, 30);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pop, 30);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_jabber, 30);

    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_netbios_tcp, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_bittorrent_tcp, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ssh, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_smb, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_nfs, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mysql, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_postgres, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_kerberos, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_redis, 40);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_oracle, 40);

    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_stun_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_telnet, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_rtp_tcp, 50); //Check STUN before RTP
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_rdp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mssql, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_sip, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_edonkey, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_fasttrack, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_gnutella, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_winmx, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_directconnect_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_msn_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_yahoo_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_oscar, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_applejuice, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_soulseek, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_irc, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_usenet, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_filetopia, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_manolito_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_imesh_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mms, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pando, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tvants_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_sopcast_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tvuplayer_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ppstream_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pplive_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_gadugadu, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_zattoo_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_qq_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_feidian_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_popo, 50); //BW: TODO: check this out
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_thunder_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_vnc, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_teamviewer_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_i23v5, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_socrates_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_steam, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_xbox, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_http_application_activesync, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_worldofwarcraft, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_flash, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_bgp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_secondlife_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pcanywhere, 50); //BW: TODO: The classification of PCANYWHERE seems to be for UDP only, check this out
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_icecast, 50); //BW: TODO: Check out the classification --- dependence on http
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_shoutcast, 50); //BW: TODO: Check out the classification --- dependence on http
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_veohtv_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_openft, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_syslog, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tds, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_direct_download_link, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ipp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ldap, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_warcraft3, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_xdmcp_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pptp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_stealthnet, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_meebo, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_afp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_aimini_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_florensia_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_maplestory, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dofus, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_world_of_kung_fu, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_fiesta, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_crossfire_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_guildwars, 50);
    /* issue #102: mmt_check_skype_tcp registration removed -- the classifier
     * matched on coincidental packet shape (no Skype protocol content
     * validation) and was a false-positive source; see proto_skype.c. */
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_citrix, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dcerpc, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_spotify, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_rtsp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tpkt, 50);
    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ndn, 60);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ndn_http, 60);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mqtt, 60);

    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp_control, 50);
    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp_data, 50);
    /***

        CLASSIFY PROTOCOL OVER UDP PROTOCOL

    ***/
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_quic, 30);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_mdns, 30); // Must be before mmt_check_dns
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dns, 30);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dhcp, 30);

    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dropbox_udp, 40);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_bittorrent_udp, 40);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ntp, 40);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_nfs, 40);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ssdp, 40);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_syslog, 40);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_netbios_udp, 40);
    /* issue #102: mmt_check_skype_udp registration removed -- the classifier
     * matched on coincidental packet shape (no Skype protocol content
     * validation) and outranked STUN/RTP (weight 50), causing their flows
     * to be mislabeled Skype; see proto_skype.c. */
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_netflow, 40);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sflow, 40);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_vmware, 40);

    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dhcpv6, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_stun_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_rtp_udp, 50); //Check STUN before RTP
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sip, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_edonkey, 50); //BW: TODO: Edonkey classification seems limited to TCP! Check this out
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_gnutella, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_directconnect_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_msn_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_yahoo_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_oscar, 50); //BW: TODO: the classification of oscar seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_jabber, 50); //BW: TODO: the classification of jabber seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_gtp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_manolito_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_imesh_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pando, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tvants_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sopcast_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tvuplayer_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ppstream_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pplive_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_iax, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_mgcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_gadugadu, 50); //BW: TODO: the classification of gadugadu seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_zattoo_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_qq_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_feidian_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_popo, 50); //BW: TODO: check this out
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_thunder_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_teamviewer_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_socrates_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_halflife2, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_xbox, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_quake, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_battlefield, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_secondlife_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pcanywhere, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_snmp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_kontiki, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_veohtv_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ipp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ldap, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_warcraft3, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_xdmcp_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tftp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_aimini_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_florensia_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_crossfire_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_armagetron, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_radius, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_eclipse_tcf, 50);
    // register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ndn, 60);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ndn_http, 60);
    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////////END OF INTER-PROTOCOL CLASSIFICATIONS ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    // M9 (issue #26): now that every tcpip protocol is registered (so protocol
    // names resolve), pull in any externally-supplied IP-range / port-hint data.
    // Both are no-ops unless MMT_DPI_IP_RANGES_FILE / MMT_DPI_PORT_MAP_FILE are
    // set, keeping the default classification byte-identical to the baseline.
    mmt_tcpip_load_external_ip_ranges();
    mmt_tcpip_load_external_port_map();

    return retval;
}

