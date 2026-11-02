/* GENERATED FILE -- do not edit by hand (issue #557).
 * Source: data/ip_ranges.txt, version 2026-11-02; regenerate with
 *   python3 tools/gen-ip-range-table.py
 * The compiled-in IPv4 attribution table of _find_proto_id_by_address(),
 * included by mmt_tcpip_classif_utils.c: 5855 prefixes flattened into 7180
 * disjoint intervals, sorted by start address. An interval runs from its
 * start to the next one's; it carries the protocol and the prefix length
 * of the longest listed prefix containing it (0 = no prefix). The first
 * interval starts at 0.0.0.0, so every address falls in exactly one. */
#define IP_RANGE_INTERVAL_COUNT 7180
static const ip_range_interval_t ip_range_intervals[IP_RANGE_INTERVAL_COUNT] = {
    {0x00000000u, PROTO_UNKNOWN, 0},
    {0x01b20100u, PROTO_AWS, 24}, /* 1.178.1.0/24 */
    {0x01b20200u, PROTO_UNKNOWN, 0},
    {0x01b20400u, PROTO_AWS, 22}, /* 1.178.4.0/22 */
    {0x01b20c00u, PROTO_UNKNOWN, 0},
    {0x01b21000u, PROTO_AWS, 20}, /* 1.178.16.0/20 */
    {0x01b22000u, PROTO_UNKNOWN, 0},
    {0x01b24000u, PROTO_AWS, 23}, /* 1.178.64.0/23 */
    {0x01b24200u, PROTO_UNKNOWN, 0},
    {0x01b24800u, PROTO_AWS, 21}, /* 1.178.72.0/21 */
    {0x01b25000u, PROTO_UNKNOWN, 0},
    {0x01b25800u, PROTO_AWS, 21}, /* 1.178.88.0/21 */
    {0x01b26000u, PROTO_UNKNOWN, 0},
    {0x01b26400u, PROTO_AWS, 22}, /* 1.178.100.0/22 */
    {0x01b26800u, PROTO_UNKNOWN, 0},
    {0x01b2ac00u, PROTO_AWS, 23}, /* 1.178.172.0/23 */
    {0x01b2ae00u, PROTO_AWS, 24}, /* 1.178.174.0/24 */
    {0x01b2af00u, PROTO_UNKNOWN, 0},
    {0x01b30200u, PROTO_AWS, 23}, /* 1.179.2.0/23 */
    {0x01b30400u, PROTO_UNKNOWN, 0},
    {0x01b30e00u, PROTO_AWS, 23}, /* 1.179.14.0/23 */
    {0x01b31000u, PROTO_UNKNOWN, 0},
    {0x01b33400u, PROTO_AWS, 22}, /* 1.179.52.0/22 */
    {0x01b33c00u, PROTO_AWS, 23}, /* 1.179.60.0/23 */
    {0x01b33e00u, PROTO_UNKNOWN, 0},
    {0x01b36500u, PROTO_AWS, 24}, /* 1.179.101.0/24 */
    {0x01b36600u, PROTO_AWS, 23}, /* 1.179.102.0/23 */
    {0x01b36800u, PROTO_UNKNOWN, 0},
    {0x01c90000u, PROTO_KAKAO, 24}, /* 1.201.0.0/24 */
    {0x01c90200u, PROTO_UNKNOWN, 0},
    {0x01c90700u, PROTO_KAKAO, 24}, /* 1.201.7.0/24 */
    {0x01c90800u, PROTO_UNKNOWN, 0},
    {0x03000000u, PROTO_AWS, 15}, /* 3.0.0.0/15 */
    {0x03020000u, PROTO_AWS, 22}, /* 3.2.0.0/22 */
    {0x03020400u, PROTO_AWS, 23}, /* 3.2.4.0/23 */
    {0x03020600u, PROTO_UNKNOWN, 0},
    {0x03020800u, PROTO_AWS, 21}, /* 3.2.8.0/21 */
    {0x03021000u, PROTO_UNKNOWN, 0},
    {0x03023000u, PROTO_AWS, 21}, /* 3.2.48.0/21 */
    {0x03023800u, PROTO_AWS, 22}, /* 3.2.56.0/22 */
    {0x03023c00u, PROTO_AWS, 23}, /* 3.2.60.0/23 */
    {0x03023e00u, PROTO_UNKNOWN, 0},
    {0x03024000u, PROTO_AWS, 18}, /* 3.2.64.0/18 */
    {0x03028000u, PROTO_UNKNOWN, 0},
    {0x03030000u, PROTO_AWS, 23}, /* 3.3.0.0/23 */
    {0x03030200u, PROTO_AWS, 24}, /* 3.3.2.0/24 */
    {0x03030300u, PROTO_UNKNOWN, 0},
    {0x03030500u, PROTO_AWS, 24}, /* 3.3.5.0/24 */
    {0x03030600u, PROTO_AWS, 23}, /* 3.3.6.0/23 */
    {0x03030800u, PROTO_AWS, 21}, /* 3.3.8.0/21 */
    {0x03031000u, PROTO_AWS, 20}, /* 3.3.16.0/20 */
    {0x03032000u, PROTO_AWS, 23}, /* 3.3.32.0/23 */
    {0x03032200u, PROTO_UNKNOWN, 0},
    {0x03040000u, PROTO_AWS, 22}, /* 3.4.0.0/22 */
    {0x03040400u, PROTO_AWS, 24}, /* 3.4.4.0/24 */
    {0x03040500u, PROTO_UNKNOWN, 0},
    {0x03040600u, PROTO_AWS, 24}, /* 3.4.6.0/24 */
    {0x03040700u, PROTO_UNKNOWN, 0},
    {0x03040800u, PROTO_AWS, 23}, /* 3.4.8.0/23 */
    {0x03040a00u, PROTO_AWS, 24}, /* 3.4.10.0/24 */
    {0x03040b00u, PROTO_UNKNOWN, 0},
    {0x03040c01u, PROTO_AWS, 32}, /* 3.4.12.1/32 */
    {0x03040c02u, PROTO_AWS, 31}, /* 3.4.12.2/31 */
    {0x03040c06u, PROTO_AWS, 32}, /* 3.4.12.6/32 */
    {0x03040c07u, PROTO_UNKNOWN, 0},
    {0x03040c0bu, PROTO_AWS, 32}, /* 3.4.12.11/32 */
    {0x03040c0du, PROTO_UNKNOWN, 0},
    {0x03040c0fu, PROTO_AWS, 32}, /* 3.4.12.15/32 */
    {0x03040c10u, PROTO_AWS, 28}, /* 3.4.12.16/28 */
    {0x03040c20u, PROTO_AWS, 29}, /* 3.4.12.32/29 */
    {0x03040c28u, PROTO_AWS, 30}, /* 3.4.12.40/30 */
    {0x03040c2cu, PROTO_AWS, 31}, /* 3.4.12.44/31 */
    {0x03040c2eu, PROTO_AWS, 32}, /* 3.4.12.46/32 */
    {0x03040c2fu, PROTO_UNKNOWN, 0},
    {0x03040c31u, PROTO_AWS, 32}, /* 3.4.12.49/32 */
    {0x03040c32u, PROTO_AWS, 31}, /* 3.4.12.50/31 */
    {0x03040c34u, PROTO_AWS, 30}, /* 3.4.12.52/30 */
    {0x03040c38u, PROTO_AWS, 29}, /* 3.4.12.56/29 */
    {0x03040c40u, PROTO_AWS, 28}, /* 3.4.12.64/28 */
    {0x03040c50u, PROTO_AWS, 30}, /* 3.4.12.80/30 */
    {0x03040c54u, PROTO_AWS, 31}, /* 3.4.12.84/31 */
    {0x03040c56u, PROTO_AWS, 32}, /* 3.4.12.86/32 */
    {0x03040c57u, PROTO_UNKNOWN, 0},
    {0x03040d00u, PROTO_AWS, 26}, /* 3.4.13.0/26 */
    {0x03040d40u, PROTO_AWS, 27}, /* 3.4.13.64/27 */
    {0x03040d60u, PROTO_UNKNOWN, 0},
    {0x03040e00u, PROTO_AWS, 27}, /* 3.4.14.0/27 */
    {0x03040e20u, PROTO_AWS, 29}, /* 3.4.14.32/29 */
    {0x03040e28u, PROTO_UNKNOWN, 0},
    {0x03040f00u, PROTO_AWS, 25}, /* 3.4.15.0/25 */
    {0x03040f80u, PROTO_AWS, 28}, /* 3.4.15.128/28 */
    {0x03040f90u, PROTO_UNKNOWN, 0},
    {0x03040f98u, PROTO_AWS, 29}, /* 3.4.15.152/29 */
    {0x03040fa0u, PROTO_AWS, 27}, /* 3.4.15.160/27 */
    {0x03040fc0u, PROTO_AWS, 26}, /* 3.4.15.192/26 */
    {0x03041000u, PROTO_AWS, 20}, /* 3.4.16.0/20 */
    {0x03043000u, PROTO_UNKNOWN, 0},
    {0x03050000u, PROTO_AWS, 18}, /* 3.5.0.0/18 */
    {0x03054000u, PROTO_AWS, 19}, /* 3.5.64.0/19 */
    {0x03056000u, PROTO_AWS, 20}, /* 3.5.96.0/20 */
    {0x03057000u, PROTO_UNKNOWN, 0},
    {0x03057800u, PROTO_AWS, 22}, /* 3.5.120.0/22 */
    {0x03057c00u, PROTO_UNKNOWN, 0},
    {0x03057e00u, PROTO_AWS, 23}, /* 3.5.126.0/23 */
    {0x03058000u, PROTO_AWS, 19}, /* 3.5.128.0/19 */
    {0x0305a000u, PROTO_AWS, 21}, /* 3.5.160.0/21 */
    {0x0305a800u, PROTO_AWS, 23}, /* 3.5.168.0/23 */
    {0x0305aa00u, PROTO_UNKNOWN, 0},
    {0x0305ac00u, PROTO_AWS, 22}, /* 3.5.172.0/22 */
    {0x0305b000u, PROTO_UNKNOWN, 0},
    {0x0305b400u, PROTO_AWS, 22}, /* 3.5.180.0/22 */
    {0x0305b800u, PROTO_AWS, 21}, /* 3.5.184.0/21 */
    {0x0305c800u, PROTO_UNKNOWN, 0},
    {0x0305ca00u, PROTO_AWS, 23}, /* 3.5.202.0/23 */
    {0x0305cc00u, PROTO_AWS, 22}, /* 3.5.204.0/22 */
    {0x0305d000u, PROTO_AWS, 20}, /* 3.5.208.0/20 */
    {0x0305e000u, PROTO_AWS, 19}, /* 3.5.224.0/19 */
    {0x03060000u, PROTO_AWS, 15}, /* 3.6.0.0/15 */
    {0x030a0000u, PROTO_AWS, 20}, /* 3.10.0.0/20 */
    {0x030a1000u, PROTO_AWS, 24}, /* 3.10.16.0/24 */
    {0x030a1100u, PROTO_AWS, 25}, /* 3.10.17.0/25 */
    {0x030a1180u, PROTO_CLOUDFRONT, 25}, /* 3.10.17.128/25 */
    {0x030a1200u, PROTO_AWS, 23}, /* 3.10.18.0/23 */
    {0x030a1400u, PROTO_AWS, 22}, /* 3.10.20.0/22 */
    {0x030a1800u, PROTO_AWS, 21}, /* 3.10.24.0/21 */
    {0x030a2000u, PROTO_AWS, 19}, /* 3.10.32.0/19 */
    {0x030a4000u, PROTO_AWS, 18}, /* 3.10.64.0/18 */
    {0x030a8000u, PROTO_AWS, 17}, /* 3.10.128.0/17 */
    {0x030b0000u, PROTO_AWS, 19}, /* 3.11.0.0/19 */
    {0x030b2000u, PROTO_AWS, 20}, /* 3.11.32.0/20 */
    {0x030b3000u, PROTO_AWS, 22}, /* 3.11.48.0/22 */
    {0x030b3400u, PROTO_AWS, 24}, /* 3.11.52.0/24 */
    {0x030b3500u, PROTO_CLOUDFRONT, 24}, /* 3.11.53.0/24 */
    {0x030b3600u, PROTO_AWS, 23}, /* 3.11.54.0/23 */
    {0x030b3800u, PROTO_AWS, 21}, /* 3.11.56.0/21 */
    {0x030b4000u, PROTO_AWS, 18}, /* 3.11.64.0/18 */
    {0x030b8000u, PROTO_AWS, 17}, /* 3.11.128.0/17 */
    {0x030c0000u, PROTO_AWS, 14}, /* 3.12.0.0/14 */
    {0x03100000u, PROTO_AWS, 13}, /* 3.16.0.0/13 */
    {0x03180000u, PROTO_AWS, 14}, /* 3.24.0.0/14 */
    {0x031c0000u, PROTO_AWS, 16}, /* 3.28.0.0/16 */
    {0x031d0000u, PROTO_AWS, 19}, /* 3.29.0.0/19 */
    {0x031d2000u, PROTO_AWS, 21}, /* 3.29.32.0/21 */
    {0x031d2800u, PROTO_AWS, 26}, /* 3.29.40.0/26 */
    {0x031d2840u, PROTO_CLOUDFRONT, 26}, /* 3.29.40.64/26 */
    {0x031d2880u, PROTO_CLOUDFRONT, 25}, /* 3.29.40.128/25 */
    {0x031d2900u, PROTO_AWS, 24}, /* 3.29.41.0/24 */
    {0x031d2a00u, PROTO_AWS, 23}, /* 3.29.42.0/23 */
    {0x031d2c00u, PROTO_AWS, 22}, /* 3.29.44.0/22 */
    {0x031d3000u, PROTO_AWS, 21}, /* 3.29.48.0/21 */
    {0x031d3800u, PROTO_AWS, 24}, /* 3.29.56.0/24 */
    {0x031d3900u, PROTO_CLOUDFRONT, 26}, /* 3.29.57.0/26 */
    {0x031d3940u, PROTO_AWS, 26}, /* 3.29.57.64/26 */
    {0x031d3980u, PROTO_AWS, 25}, /* 3.29.57.128/25 */
    {0x031d3a00u, PROTO_AWS, 23}, /* 3.29.58.0/23 */
    {0x031d3c00u, PROTO_AWS, 22}, /* 3.29.60.0/22 */
    {0x031d4000u, PROTO_AWS, 18}, /* 3.29.64.0/18 */
    {0x031d8000u, PROTO_AWS, 17}, /* 3.29.128.0/17 */
    {0x031e0000u, PROTO_AWS, 15}, /* 3.30.0.0/15 */
    {0x03200000u, PROTO_AWS, 16}, /* 3.32.0.0/16 */
    {0x03210000u, PROTO_AWS, 23}, /* 3.33.0.0/23 */
    {0x03210200u, PROTO_UNKNOWN, 0},
    {0x03212c00u, PROTO_AWS, 22}, /* 3.33.44.0/22 */
    {0x03213000u, PROTO_UNKNOWN, 0},
    {0x03218000u, PROTO_AWS, 17}, /* 3.33.128.0/17 */
    {0x03220000u, PROTO_AWS, 16}, /* 3.34.0.0/16 */
    {0x03230000u, PROTO_AWS, 17}, /* 3.35.0.0/17 */
    {0x03238000u, PROTO_AWS, 23}, /* 3.35.128.0/23 */
    {0x03238200u, PROTO_AWS, 25}, /* 3.35.130.0/25 */
    {0x03238280u, PROTO_CLOUDFRONT, 25}, /* 3.35.130.128/25 */
    {0x03238300u, PROTO_AWS, 24}, /* 3.35.131.0/24 */
    {0x03238400u, PROTO_AWS, 22}, /* 3.35.132.0/22 */
    {0x03238800u, PROTO_AWS, 21}, /* 3.35.136.0/21 */
    {0x03239000u, PROTO_AWS, 20}, /* 3.35.144.0/20 */
    {0x0323a000u, PROTO_AWS, 19}, /* 3.35.160.0/19 */
    {0x0323c000u, PROTO_AWS, 18}, /* 3.35.192.0/18 */
    {0x03240000u, PROTO_AWS, 14}, /* 3.36.0.0/14 */
    {0x032c0000u, PROTO_AWS, 16}, /* 3.44.0.0/16 */
    {0x032d0000u, PROTO_AWS, 17}, /* 3.45.0.0/17 */
    {0x032d8000u, PROTO_UNKNOWN, 0},
    {0x03400000u, PROTO_AWS, 11}, /* 3.64.0.0/11 */
    {0x03600000u, PROTO_AWS, 14}, /* 3.96.0.0/14 */
    {0x03640000u, PROTO_UNKNOWN, 0},
    {0x03650000u, PROTO_AWS, 17}, /* 3.101.0.0/17 */
    {0x03658000u, PROTO_AWS, 20}, /* 3.101.128.0/20 */
    {0x03659000u, PROTO_AWS, 21}, /* 3.101.144.0/21 */
    {0x03659800u, PROTO_AWS, 22}, /* 3.101.152.0/22 */
    {0x03659c00u, PROTO_AWS, 23}, /* 3.101.156.0/23 */
    {0x03659e00u, PROTO_CLOUDFRONT, 23}, /* 3.101.158.0/23 */
    {0x0365a000u, PROTO_AWS, 19}, /* 3.101.160.0/19 */
    {0x0365c000u, PROTO_AWS, 18}, /* 3.101.192.0/18 */
    {0x03660000u, PROTO_AWS, 15}, /* 3.102.0.0/15 */
    {0x036a0000u, PROTO_AWS, 16}, /* 3.106.0.0/16 */
    {0x036b0000u, PROTO_AWS, 19}, /* 3.107.0.0/19 */
    {0x036b2000u, PROTO_AWS, 21}, /* 3.107.32.0/21 */
    {0x036b2800u, PROTO_AWS, 23}, /* 3.107.40.0/23 */
    {0x036b2a00u, PROTO_AWS, 24}, /* 3.107.42.0/24 */
    {0x036b2b00u, PROTO_AWS, 25}, /* 3.107.43.0/25 */
    {0x036b2b80u, PROTO_CLOUDFRONT, 25}, /* 3.107.43.128/25 */
    {0x036b2c00u, PROTO_CLOUDFRONT, 24}, /* 3.107.44.0/24 */
    {0x036b2d00u, PROTO_AWS, 24}, /* 3.107.45.0/24 */
    {0x036b2e00u, PROTO_AWS, 23}, /* 3.107.46.0/23 */
    {0x036b3000u, PROTO_AWS, 20}, /* 3.107.48.0/20 */
    {0x036b4000u, PROTO_AWS, 18}, /* 3.107.64.0/18 */
    {0x036b8000u, PROTO_AWS, 17}, /* 3.107.128.0/17 */
    {0x036c0000u, PROTO_AWS, 14}, /* 3.108.0.0/14 */
    {0x03740000u, PROTO_UNKNOWN, 0},
    {0x03780000u, PROTO_AWS, 13}, /* 3.120.0.0/13 */
    {0x03800000u, PROTO_AWS, 18}, /* 3.128.0.0/18 */
    {0x03804000u, PROTO_AWS, 20}, /* 3.128.64.0/20 */
    {0x03805000u, PROTO_AWS, 21}, /* 3.128.80.0/21 */
    {0x03805800u, PROTO_AWS, 22}, /* 3.128.88.0/22 */
    {0x03805c00u, PROTO_AWS, 24}, /* 3.128.92.0/24 */
    {0x03805d00u, PROTO_CLOUDFRONT, 24}, /* 3.128.93.0/24 */
    {0x03805e00u, PROTO_AWS, 23}, /* 3.128.94.0/23 */
    {0x03806000u, PROTO_AWS, 19}, /* 3.128.96.0/19 */
    {0x03808000u, PROTO_AWS, 17}, /* 3.128.128.0/17 */
    {0x03810000u, PROTO_AWS, 16}, /* 3.129.0.0/16 */
    {0x03820000u, PROTO_AWS, 15}, /* 3.130.0.0/15 */
    {0x03860000u, PROTO_AWS, 17}, /* 3.134.0.0/17 */
    {0x03868000u, PROTO_AWS, 18}, /* 3.134.128.0/18 */
    {0x0386c000u, PROTO_AWS, 20}, /* 3.134.192.0/20 */
    {0x0386d000u, PROTO_AWS, 22}, /* 3.134.208.0/22 */
    {0x0386d400u, PROTO_AWS, 23}, /* 3.134.212.0/23 */
    {0x0386d600u, PROTO_AWS, 24}, /* 3.134.214.0/24 */
    {0x0386d700u, PROTO_CLOUDFRONT, 24}, /* 3.134.215.0/24 */
    {0x0386d800u, PROTO_AWS, 21}, /* 3.134.216.0/21 */
    {0x0386e000u, PROTO_AWS, 19}, /* 3.134.224.0/19 */
    {0x03870000u, PROTO_AWS, 16}, /* 3.135.0.0/16 */
    {0x03880000u, PROTO_AWS, 13}, /* 3.136.0.0/13 */
    {0x03900000u, PROTO_AWS, 15}, /* 3.144.0.0/15 */
    {0x03920000u, PROTO_AWS, 17}, /* 3.146.0.0/17 */
    {0x03928000u, PROTO_AWS, 18}, /* 3.146.128.0/18 */
    {0x0392c000u, PROTO_AWS, 19}, /* 3.146.192.0/19 */
    {0x0392e000u, PROTO_AWS, 21}, /* 3.146.224.0/21 */
    {0x0392e800u, PROTO_CLOUDFRONT, 22}, /* 3.146.232.0/22 */
    {0x0392ec00u, PROTO_AWS, 22}, /* 3.146.236.0/22 */
    {0x0392f000u, PROTO_AWS, 20}, /* 3.146.240.0/20 */
    {0x03930000u, PROTO_AWS, 17}, /* 3.147.0.0/17 */
    {0x03938000u, PROTO_AWS, 19}, /* 3.147.128.0/19 */
    {0x0393a000u, PROTO_AWS, 22}, /* 3.147.160.0/22 */
    {0x0393a400u, PROTO_CLOUDFRONT, 22}, /* 3.147.164.0/22 */
    {0x0393a800u, PROTO_AWS, 21}, /* 3.147.168.0/21 */
    {0x0393b000u, PROTO_AWS, 20}, /* 3.147.176.0/20 */
    {0x0393c000u, PROTO_AWS, 19}, /* 3.147.192.0/19 */
    {0x0393e000u, PROTO_AWS, 20}, /* 3.147.224.0/20 */
    {0x0393f000u, PROTO_AWS, 22}, /* 3.147.240.0/22 */
    {0x0393f400u, PROTO_CLOUDFRONT, 22}, /* 3.147.244.0/22 */
    {0x0393f800u, PROTO_AWS, 21}, /* 3.147.248.0/21 */
    {0x03940000u, PROTO_AWS, 14}, /* 3.148.0.0/14 */
    {0x03980000u, PROTO_UNKNOWN, 0},
    {0x03a00000u, PROTO_CLOUDFRONT, 13}, /* 3.160.0.0/13 */
    {0x03a80000u, PROTO_CLOUDFRONT, 14}, /* 3.168.0.0/14 */
    {0x03ac0000u, PROTO_CLOUDFRONT, 17}, /* 3.172.0.0/17 */
    {0x03ac8000u, PROTO_UNKNOWN, 0},
    {0x03ad0000u, PROTO_CLOUDFRONT, 16}, /* 3.173.0.0/16 */
    {0x03ae0000u, PROTO_CLOUDFRONT, 15}, /* 3.174.0.0/15 */
    {0x03b00000u, PROTO_UNKNOWN, 0},
    {0x03d00000u, PROTO_AWS, 12}, /* 3.208.0.0/12 */
    {0x03e00000u, PROTO_AWS, 14}, /* 3.224.0.0/14 */
    {0x03e40000u, PROTO_AWS, 15}, /* 3.228.0.0/15 */
    {0x03e60000u, PROTO_AWS, 16}, /* 3.230.0.0/16 */
    {0x03e70000u, PROTO_AWS, 23}, /* 3.231.0.0/23 */
    {0x03e70200u, PROTO_CLOUDFRONT, 25}, /* 3.231.2.0/25 */
    {0x03e70280u, PROTO_AWS, 25}, /* 3.231.2.128/25 */
    {0x03e70300u, PROTO_AWS, 24}, /* 3.231.3.0/24 */
    {0x03e70400u, PROTO_AWS, 22}, /* 3.231.4.0/22 */
    {0x03e70800u, PROTO_AWS, 21}, /* 3.231.8.0/21 */
    {0x03e71000u, PROTO_AWS, 20}, /* 3.231.16.0/20 */
    {0x03e72000u, PROTO_AWS, 19}, /* 3.231.32.0/19 */
    {0x03e74000u, PROTO_AWS, 18}, /* 3.231.64.0/18 */
    {0x03e78000u, PROTO_AWS, 17}, /* 3.231.128.0/17 */
    {0x03e80000u, PROTO_AWS, 15}, /* 3.232.0.0/15 */
    {0x03ea0000u, PROTO_AWS, 17}, /* 3.234.0.0/17 */
    {0x03ea8000u, PROTO_AWS, 18}, /* 3.234.128.0/18 */
    {0x03eac000u, PROTO_AWS, 19}, /* 3.234.192.0/19 */
    {0x03eae000u, PROTO_AWS, 21}, /* 3.234.224.0/21 */
    {0x03eae800u, PROTO_AWS, 25}, /* 3.234.232.0/25 */
    {0x03eae880u, PROTO_AWS, 26}, /* 3.234.232.128/26 */
    {0x03eae8c0u, PROTO_AWS, 27}, /* 3.234.232.192/27 */
    {0x03eae8e0u, PROTO_CLOUDFRONT, 27}, /* 3.234.232.224/27 */
    {0x03eae900u, PROTO_AWS, 24}, /* 3.234.233.0/24 */
    {0x03eaea00u, PROTO_AWS, 23}, /* 3.234.234.0/23 */
    {0x03eaec00u, PROTO_AWS, 22}, /* 3.234.236.0/22 */
    {0x03eaf000u, PROTO_AWS, 20}, /* 3.234.240.0/20 */
    {0x03eb0000u, PROTO_AWS, 16}, /* 3.235.0.0/16 */
    {0x03ec0000u, PROTO_AWS, 19}, /* 3.236.0.0/19 */
    {0x03ec2000u, PROTO_AWS, 20}, /* 3.236.32.0/20 */
    {0x03ec3000u, PROTO_CLOUDFRONT, 23}, /* 3.236.48.0/23 */
    {0x03ec3200u, PROTO_AWS, 23}, /* 3.236.50.0/23 */
    {0x03ec3400u, PROTO_AWS, 22}, /* 3.236.52.0/22 */
    {0x03ec3800u, PROTO_AWS, 21}, /* 3.236.56.0/21 */
    {0x03ec4000u, PROTO_AWS, 18}, /* 3.236.64.0/18 */
    {0x03ec8000u, PROTO_AWS, 19}, /* 3.236.128.0/19 */
    {0x03eca000u, PROTO_AWS, 21}, /* 3.236.160.0/21 */
    {0x03eca800u, PROTO_AWS, 24}, /* 3.236.168.0/24 */
    {0x03eca900u, PROTO_AWS, 25}, /* 3.236.169.0/25 */
    {0x03eca980u, PROTO_AWS, 26}, /* 3.236.169.128/26 */
    {0x03eca9c0u, PROTO_CLOUDFRONT, 26}, /* 3.236.169.192/26 */
    {0x03ecaa00u, PROTO_AWS, 23}, /* 3.236.170.0/23 */
    {0x03ecac00u, PROTO_AWS, 22}, /* 3.236.172.0/22 */
    {0x03ecb000u, PROTO_AWS, 20}, /* 3.236.176.0/20 */
    {0x03ecc000u, PROTO_AWS, 18}, /* 3.236.192.0/18 */
    {0x03ed0000u, PROTO_AWS, 16}, /* 3.237.0.0/16 */
    {0x03ee0000u, PROTO_AWS, 15}, /* 3.238.0.0/15 */
    {0x03f00000u, PROTO_UNKNOWN, 0},
    {0x03f80000u, PROTO_AWS, 13}, /* 3.248.0.0/13 */
    {0x04000000u, PROTO_UNKNOWN, 0},
    {0x04900000u, PROTO_AZURE, 12}, /* 4.144.0.0/12 */
    {0x04a00000u, PROTO_AZURE, 11}, /* 4.160.0.0/11 */
    {0x04c00000u, PROTO_AZURE, 10}, /* 4.192.0.0/10 */
    {0x05000000u, PROTO_UNKNOWN, 0},
    {0x053c0000u, PROTO_AWS, 20}, /* 5.60.0.0/20 */
    {0x053c1000u, PROTO_AWS, 24}, /* 5.60.16.0/24 */
    {0x053c1100u, PROTO_UNKNOWN, 0},
    {0x053c2000u, PROTO_AWS, 19}, /* 5.60.32.0/19 */
    {0x053c4000u, PROTO_AWS, 18}, /* 5.60.64.0/18 */
    {0x053c8000u, PROTO_AWS, 17}, /* 5.60.128.0/17 */
    {0x053d0000u, PROTO_UNKNOWN, 0},
    {0x05ae0000u, PROTO_AWS, 16}, /* 5.174.0.0/16 */
    {0x05af0000u, PROTO_UNKNOWN, 0},
    {0x05b36000u, PROTO_AWS, 20}, /* 5.179.96.0/20 */
    {0x05b37000u, PROTO_UNKNOWN, 0},
    {0x08080400u, PROTO_GOOGLE, 24}, /* 8.8.4.0/24 */
    {0x08080500u, PROTO_UNKNOWN, 0},
    {0x08080800u, PROTO_GOOGLE, 24}, /* 8.8.8.0/24 */
    {0x08080900u, PROTO_UNKNOWN, 0},
    {0x0819c000u, PROTO_WEBEX, 24}, /* 8.25.192.0/24 */
    {0x0819c100u, PROTO_UNKNOWN, 0},
    {0x0819c200u, PROTO_TWITTER, 23}, /* 8.25.194.0/23 */
    {0x0819c300u, PROTO_TWITTER, 24}, /* 8.25.195.0/24 */
    {0x0819c400u, PROTO_TWITTER, 23}, /* 8.25.196.0/23 */
    {0x0819c500u, PROTO_TWITTER, 24}, /* 8.25.197.0/24 */
    {0x0819c600u, PROTO_UNKNOWN, 0},
    {0x0822d000u, PROTO_GOOGLE_CLOUD, 20}, /* 8.34.208.0/20 */
    {0x0822e000u, PROTO_UNKNOWN, 0},
    {0x0823c000u, PROTO_GOOGLE_CLOUD, 21}, /* 8.35.192.0/21 */
    {0x0823c800u, PROTO_GOOGLE, 21}, /* 8.35.200.0/21 */
    {0x0823d000u, PROTO_UNKNOWN, 0},
    {0x08e40000u, PROTO_GOOGLE_CLOUD, 15}, /* 8.228.0.0/15 */
    {0x08e60000u, PROTO_GOOGLE_CLOUD, 17}, /* 8.230.0.0/17 */
    {0x08e68000u, PROTO_GOOGLE, 17}, /* 8.230.128.0/17 */
    {0x08e70000u, PROTO_GOOGLE, 19}, /* 8.231.0.0/19 */
    {0x08e72000u, PROTO_GOOGLE_CLOUD, 19}, /* 8.231.32.0/19 */
    {0x08e74000u, PROTO_GOOGLE_CLOUD, 18}, /* 8.231.64.0/18 */
    {0x08e78000u, PROTO_GOOGLE_CLOUD, 17}, /* 8.231.128.0/17 */
    {0x08e80000u, PROTO_GOOGLE_CLOUD, 15}, /* 8.232.0.0/15 */
    {0x08ea0000u, PROTO_GOOGLE, 23}, /* 8.234.0.0/23 */
    {0x08ea0200u, PROTO_GOOGLE_CLOUD, 23}, /* 8.234.2.0/23 */
    {0x08ea0400u, PROTO_GOOGLE_CLOUD, 22}, /* 8.234.4.0/22 */
    {0x08ea0800u, PROTO_GOOGLE_CLOUD, 21}, /* 8.234.8.0/21 */
    {0x08ea1000u, PROTO_GOOGLE_CLOUD, 23}, /* 8.234.16.0/23 */
    {0x08ea1200u, PROTO_GOOGLE, 23}, /* 8.234.18.0/23 */
    {0x08ea1400u, PROTO_GOOGLE_CLOUD, 22}, /* 8.234.20.0/22 */
    {0x08ea1800u, PROTO_GOOGLE_CLOUD, 21}, /* 8.234.24.0/21 */
    {0x08ea2000u, PROTO_GOOGLE_CLOUD, 19}, /* 8.234.32.0/19 */
    {0x08ea4000u, PROTO_GOOGLE_CLOUD, 18}, /* 8.234.64.0/18 */
    {0x08ea8000u, PROTO_GOOGLE_CLOUD, 17}, /* 8.234.128.0/17 */
    {0x08eb0000u, PROTO_GOOGLE_CLOUD, 16}, /* 8.235.0.0/16 */
    {0x08ec0000u, PROTO_GOOGLE, 17}, /* 8.236.0.0/17 */
    {0x08ec8000u, PROTO_GOOGLE, 20}, /* 8.236.128.0/20 */
    {0x08ec9000u, PROTO_GOOGLE_CLOUD, 20}, /* 8.236.144.0/20 */
    {0x08eca000u, PROTO_GOOGLE, 19}, /* 8.236.160.0/19 */
    {0x08ecc000u, PROTO_GOOGLE_CLOUD, 18}, /* 8.236.192.0/18 */
    {0x08ed0000u, PROTO_GOOGLE_CLOUD, 17}, /* 8.237.0.0/17 */
    {0x08ed8000u, PROTO_GOOGLE, 19}, /* 8.237.128.0/19 */
    {0x08eda000u, PROTO_GOOGLE_CLOUD, 19}, /* 8.237.160.0/19 */
    {0x08edc000u, PROTO_GOOGLE_CLOUD, 18}, /* 8.237.192.0/18 */
    {0x08ee0000u, PROTO_UNKNOWN, 0},
    {0x09810000u, PROTO_AZURE, 16}, /* 9.129.0.0/16 */
    {0x09820000u, PROTO_UNKNOWN, 0},
    {0x098d0000u, PROTO_AZURE, 16}, /* 9.141.0.0/16 */
    {0x098e0000u, PROTO_UNKNOWN, 0},
    {0x09a00000u, PROTO_AZURE, 16}, /* 9.160.0.0/16 */
    {0x09a10000u, PROTO_UNKNOWN, 0},
    {0x09a30000u, PROTO_AZURE, 16}, /* 9.163.0.0/16 */
    {0x09a40000u, PROTO_UNKNOWN, 0},
    {0x09a90000u, PROTO_AZURE, 16}, /* 9.169.0.0/16 */
    {0x09aa0000u, PROTO_UNKNOWN, 0},
    {0x09cd0000u, PROTO_AZURE, 16}, /* 9.205.0.0/16 */
    {0x09ce0000u, PROTO_UNKNOWN, 0},
    {0x09df0000u, PROTO_AZURE, 16}, /* 9.223.0.0/16 */
    {0x09e00000u, PROTO_UNKNOWN, 0},
    {0x09ea0000u, PROTO_AZURE, 15}, /* 9.234.0.0/15 */
    {0x09ec0000u, PROTO_UNKNOWN, 0},
    {0x0c117b00u, PROTO_YAHOO, 24}, /* 12.17.123.0/24 */
    {0x0c117c00u, PROTO_UNKNOWN, 0},
    {0x0d200000u, PROTO_CLOUDFRONT, 15}, /* 13.32.0.0/15 */
    {0x0d220000u, PROTO_UNKNOWN, 0},
    {0x0d230000u, PROTO_CLOUDFRONT, 16}, /* 13.35.0.0/16 */
    {0x0d240000u, PROTO_AWS, 14}, /* 13.36.0.0/14 */
    {0x0d2c0000u, PROTO_UNKNOWN, 0},
    {0x0d300000u, PROTO_AWS, 14}, /* 13.48.0.0/14 */
    {0x0d340000u, PROTO_AWS, 15}, /* 13.52.0.0/15 */
    {0x0d360000u, PROTO_AWS, 19}, /* 13.54.0.0/19 */
    {0x0d362000u, PROTO_AWS, 20}, /* 13.54.32.0/20 */
    {0x0d363000u, PROTO_AWS, 21}, /* 13.54.48.0/21 */
    {0x0d363800u, PROTO_AWS, 22}, /* 13.54.56.0/22 */
    {0x0d363c00u, PROTO_AWS, 23}, /* 13.54.60.0/23 */
    {0x0d363e00u, PROTO_AWS, 24}, /* 13.54.62.0/24 */
    {0x0d363f00u, PROTO_AWS, 25}, /* 13.54.63.0/25 */
    {0x0d363f80u, PROTO_CLOUDFRONT, 26}, /* 13.54.63.128/26 */
    {0x0d363fc0u, PROTO_AWS, 26}, /* 13.54.63.192/26 */
    {0x0d364000u, PROTO_AWS, 18}, /* 13.54.64.0/18 */
    {0x0d368000u, PROTO_AWS, 17}, /* 13.54.128.0/17 */
    {0x0d370000u, PROTO_AWS, 16}, /* 13.55.0.0/16 */
    {0x0d380000u, PROTO_AWS, 15}, /* 13.56.0.0/15 */
    {0x0d3a0000u, PROTO_AWS, 16}, /* 13.58.0.0/16 */
    {0x0d3b0000u, PROTO_AWS, 17}, /* 13.59.0.0/17 */
    {0x0d3b8000u, PROTO_AWS, 18}, /* 13.59.128.0/18 */
    {0x0d3bc000u, PROTO_AWS, 19}, /* 13.59.192.0/19 */
    {0x0d3be000u, PROTO_AWS, 20}, /* 13.59.224.0/20 */
    {0x0d3bf000u, PROTO_AWS, 21}, /* 13.59.240.0/21 */
    {0x0d3bf800u, PROTO_AWS, 23}, /* 13.59.248.0/23 */
    {0x0d3bfa00u, PROTO_CLOUDFRONT, 26}, /* 13.59.250.0/26 */
    {0x0d3bfa40u, PROTO_AWS, 26}, /* 13.59.250.64/26 */
    {0x0d3bfa80u, PROTO_AWS, 25}, /* 13.59.250.128/25 */
    {0x0d3bfb00u, PROTO_AWS, 24}, /* 13.59.251.0/24 */
    {0x0d3bfc00u, PROTO_AWS, 22}, /* 13.59.252.0/22 */
    {0x0d3c0000u, PROTO_AWS, 14}, /* 13.60.0.0/14 */
    {0x0d400000u, PROTO_AZURE, 13}, /* 13.64.0.0/13 */
    {0x0d480000u, PROTO_UNKNOWN, 0},
    {0x0d484000u, PROTO_AZURE, 18}, /* 13.72.64.0/18 */
    {0x0d488000u, PROTO_UNKNOWN, 0},
    {0x0d48c000u, PROTO_AZURE, 18}, /* 13.72.192.0/18 */
    {0x0d494000u, PROTO_UNKNOWN, 0},
    {0x0d496000u, PROTO_AZURE, 19}, /* 13.73.96.0/19 */
    {0x0d498000u, PROTO_AZURE, 18}, /* 13.73.128.0/18 */
    {0x0d49c000u, PROTO_AZURE, 20}, /* 13.73.192.0/20 */
    {0x0d49d000u, PROTO_UNKNOWN, 0},
    {0x0d49e000u, PROTO_AZURE, 19}, /* 13.73.224.0/19 */
    {0x0d4a0000u, PROTO_AZURE, 15}, /* 13.74.0.0/15 */
    {0x0d4c0000u, PROTO_AZURE, 16}, /* 13.76.0.0/16 */
    {0x0d4d0000u, PROTO_AZURE, 17}, /* 13.77.0.0/17 */
    {0x0d4d8000u, PROTO_AZURE, 18}, /* 13.77.128.0/18 */
    {0x0d4dc000u, PROTO_AZURE, 19}, /* 13.77.192.0/19 */
    {0x0d4de000u, PROTO_UNKNOWN, 0},
    {0x0d4e0000u, PROTO_AZURE, 15}, /* 13.78.0.0/15 */
    {0x0d500000u, PROTO_AZURE, 12}, /* 13.80.0.0/12 */
    {0x0d600000u, PROTO_UNKNOWN, 0},
    {0x0d688000u, PROTO_AZURE, 23}, /* 13.104.128.0/23 */
    {0x0d688200u, PROTO_UNKNOWN, 0},
    {0x0d689000u, PROTO_AZURE, 20}, /* 13.104.144.0/20 */
    {0x0d68a000u, PROTO_UNKNOWN, 0},
    {0x0d68a300u, PROTO_AZURE, 24}, /* 13.104.163.0/24 */
    {0x0d68a400u, PROTO_UNKNOWN, 0},
    {0x0d68a900u, PROTO_AZURE, 24}, /* 13.104.169.0/24 */
    {0x0d68aa00u, PROTO_UNKNOWN, 0},
    {0x0d68ad00u, PROTO_AZURE, 24}, /* 13.104.173.0/24 */
    {0x0d68ae00u, PROTO_UNKNOWN, 0},
    {0x0d68c000u, PROTO_AZURE, 21}, /* 13.104.192.0/21 */
    {0x0d68c800u, PROTO_UNKNOWN, 0},
    {0x0d68cf00u, PROTO_AZURE, 24}, /* 13.104.207.0/24 */
    {0x0d68d000u, PROTO_AZURE, 20}, /* 13.104.208.0/20 */
    {0x0d68e000u, PROTO_UNKNOWN, 0},
    {0x0d690e00u, PROTO_AZURE, 24}, /* 13.105.14.0/24 */
    {0x0d690f00u, PROTO_UNKNOWN, 0},
    {0x0d691000u, PROTO_AZURE, 20}, /* 13.105.16.0/20 */
    {0x0d692000u, PROTO_UNKNOWN, 0},
    {0x0d692400u, PROTO_AZURE, 23}, /* 13.105.36.0/23 */
    {0x0d692600u, PROTO_UNKNOWN, 0},
    {0x0d692e00u, PROTO_AZURE, 23}, /* 13.105.46.0/23 */
    {0x0d693000u, PROTO_UNKNOWN, 0},
    {0x0d693400u, PROTO_AZURE, 23}, /* 13.105.52.0/23 */
    {0x0d693600u, PROTO_UNKNOWN, 0},
    {0x0d693c00u, PROTO_AZURE, 23}, /* 13.105.60.0/23 */
    {0x0d693e00u, PROTO_UNKNOWN, 0},
    {0x0d694200u, PROTO_AZURE, 23}, /* 13.105.66.0/23 */
    {0x0d694400u, PROTO_UNKNOWN, 0},
    {0x0d694a00u, PROTO_AZURE, 23}, /* 13.105.74.0/23 */
    {0x0d694c00u, PROTO_UNKNOWN, 0},
    {0x0d696000u, PROTO_AZURE, 20}, /* 13.105.96.0/20 */
    {0x0d697000u, PROTO_UNKNOWN, 0},
    {0x0d697258u, PROTO_AZURE, 29}, /* 13.105.114.88/29 */
    {0x0d697260u, PROTO_AZURE, 27}, /* 13.105.114.96/27 */
    {0x0d697280u, PROTO_AZURE, 26}, /* 13.105.114.128/26 */
    {0x0d6972c0u, PROTO_AZURE, 28}, /* 13.105.114.192/28 */
    {0x0d6972d0u, PROTO_AZURE, 29}, /* 13.105.114.208/29 */
    {0x0d6972d8u, PROTO_UNKNOWN, 0},
    {0x0d697400u, PROTO_AZURE, 25}, /* 13.105.116.0/25 */
    {0x0d697480u, PROTO_UNKNOWN, 0},
    {0x0d69e900u, PROTO_AZURE, 24}, /* 13.105.233.0/24 */
    {0x0d69ea00u, PROTO_UNKNOWN, 0},
    {0x0d6a0200u, PROTO_AZURE, 23}, /* 13.106.2.0/23 */
    {0x0d6a0400u, PROTO_UNKNOWN, 0},
    {0x0d700000u, PROTO_AWS, 16}, /* 13.112.0.0/16 */
    {0x0d710000u, PROTO_AWS, 17}, /* 13.113.0.0/17 */
    {0x0d718000u, PROTO_AWS, 18}, /* 13.113.128.0/18 */
    {0x0d71c000u, PROTO_AWS, 22}, /* 13.113.192.0/22 */
    {0x0d71c400u, PROTO_AWS, 26}, /* 13.113.196.0/26 */
    {0x0d71c440u, PROTO_CLOUDFRONT, 26}, /* 13.113.196.64/26 */
    {0x0d71c480u, PROTO_AWS, 25}, /* 13.113.196.128/25 */
    {0x0d71c500u, PROTO_AWS, 24}, /* 13.113.197.0/24 */
    {0x0d71c600u, PROTO_AWS, 23}, /* 13.113.198.0/23 */
    {0x0d71ca00u, PROTO_AWS, 24}, /* 13.113.202.0/24 */
    {0x0d71cb00u, PROTO_CLOUDFRONT, 24}, /* 13.113.203.0/24 */
    {0x0d71cc00u, PROTO_AWS, 22}, /* 13.113.204.0/22 */
    {0x0d71d000u, PROTO_AWS, 20}, /* 13.113.208.0/20 */
    {0x0d71e000u, PROTO_AWS, 19}, /* 13.113.224.0/19 */
    {0x0d720000u, PROTO_AWS, 15}, /* 13.114.0.0/15 */
    {0x0d740000u, PROTO_UNKNOWN, 0},
    {0x0d7c0000u, PROTO_AWS, 17}, /* 13.124.0.0/17 */
    {0x0d7c8000u, PROTO_AWS, 18}, /* 13.124.128.0/18 */
    {0x0d7cc000u, PROTO_AWS, 22}, /* 13.124.192.0/22 */
    {0x0d7cc400u, PROTO_AWS, 23}, /* 13.124.196.0/23 */
    {0x0d7cc600u, PROTO_AWS, 24}, /* 13.124.198.0/24 */
    {0x0d7cc700u, PROTO_CLOUDFRONT, 24}, /* 13.124.199.0/24 */
    {0x0d7cc800u, PROTO_AWS, 21}, /* 13.124.200.0/21 */
    {0x0d7cd000u, PROTO_AWS, 20}, /* 13.124.208.0/20 */
    {0x0d7ce000u, PROTO_AWS, 19}, /* 13.124.224.0/19 */
    {0x0d7d0000u, PROTO_AWS, 16}, /* 13.125.0.0/16 */
    {0x0d7e0000u, PROTO_AWS, 15}, /* 13.126.0.0/15 */
    {0x0d800000u, PROTO_AWS, 16}, /* 13.128.0.0/16 */
    {0x0d810000u, PROTO_UNKNOWN, 0},
    {0x0d820000u, PROTO_AWS, 16}, /* 13.130.0.0/16 */
    {0x0d830000u, PROTO_UNKNOWN, 0},
    {0x0d860000u, PROTO_AWS, 20}, /* 13.134.0.0/20 */
    {0x0d861000u, PROTO_AWS, 21}, /* 13.134.16.0/21 */
    {0x0d861800u, PROTO_CLOUDFRONT, 23}, /* 13.134.24.0/23 */
    {0x0d861a00u, PROTO_AWS, 23}, /* 13.134.26.0/23 */
    {0x0d861c00u, PROTO_AWS, 22}, /* 13.134.28.0/22 */
    {0x0d862000u, PROTO_AWS, 19}, /* 13.134.32.0/19 */
    {0x0d864000u, PROTO_AWS, 20}, /* 13.134.64.0/20 */
    {0x0d865000u, PROTO_AWS, 21}, /* 13.134.80.0/21 */
    {0x0d865800u, PROTO_AWS, 22}, /* 13.134.88.0/22 */
    {0x0d865c00u, PROTO_AWS, 23}, /* 13.134.92.0/23 */
    {0x0d865e00u, PROTO_CLOUDFRONT, 23}, /* 13.134.94.0/23 */
    {0x0d866000u, PROTO_AWS, 19}, /* 13.134.96.0/19 */
    {0x0d868000u, PROTO_AWS, 17}, /* 13.134.128.0/17 */
    {0x0d870000u, PROTO_AWS, 16}, /* 13.135.0.0/16 */
    {0x0d880000u, PROTO_UNKNOWN, 0},
    {0x0d900000u, PROTO_AWS, 16}, /* 13.144.0.0/16 */
    {0x0d910000u, PROTO_UNKNOWN, 0},
    {0x0d920000u, PROTO_AWS, 16}, /* 13.146.0.0/16 */
    {0x0d930000u, PROTO_UNKNOWN, 0},
    {0x0d960000u, PROTO_AWS, 15}, /* 13.150.0.0/15 */
    {0x0d980000u, PROTO_AWS, 16}, /* 13.152.0.0/16 */
    {0x0d990000u, PROTO_UNKNOWN, 0},
    {0x0d9a0000u, PROTO_AWS, 16}, /* 13.154.0.0/16 */
    {0x0d9b0000u, PROTO_UNKNOWN, 0},
    {0x0d9e0000u, PROTO_AWS, 15}, /* 13.158.0.0/15 */
    {0x0da00000u, PROTO_AWS, 16}, /* 13.160.0.0/16 */
    {0x0da10000u, PROTO_UNKNOWN, 0},
    {0x0da20000u, PROTO_AWS, 16}, /* 13.162.0.0/16 */
    {0x0da30000u, PROTO_UNKNOWN, 0},
    {0x0da60000u, PROTO_AWS, 15}, /* 13.166.0.0/15 */
    {0x0da80000u, PROTO_UNKNOWN, 0},
    {0x0db80000u, PROTO_AWS, 13}, /* 13.184.0.0/13 */
    {0x0dc80000u, PROTO_AWS, 15}, /* 13.200.0.0/15 */
    {0x0dca0000u, PROTO_AWS, 16}, /* 13.202.0.0/16 */
    {0x0dcb0000u, PROTO_AWS, 17}, /* 13.203.0.0/17 */
    {0x0dcb8000u, PROTO_AWS, 22}, /* 13.203.128.0/22 */
    {0x0dcb8400u, PROTO_AWS, 24}, /* 13.203.132.0/24 */
    {0x0dcb8500u, PROTO_CLOUDFRONT, 26}, /* 13.203.133.0/26 */
    {0x0dcb8540u, PROTO_AWS, 26}, /* 13.203.133.64/26 */
    {0x0dcb8580u, PROTO_AWS, 25}, /* 13.203.133.128/25 */
    {0x0dcb8600u, PROTO_AWS, 23}, /* 13.203.134.0/23 */
    {0x0dcb8800u, PROTO_AWS, 21}, /* 13.203.136.0/21 */
    {0x0dcb9000u, PROTO_AWS, 20}, /* 13.203.144.0/20 */
    {0x0dcba000u, PROTO_AWS, 19}, /* 13.203.160.0/19 */
    {0x0dcbc000u, PROTO_AWS, 18}, /* 13.203.192.0/18 */
    {0x0dcc0000u, PROTO_AWS, 14}, /* 13.204.0.0/14 */
    {0x0dd00000u, PROTO_AWS, 15}, /* 13.208.0.0/15 */
    {0x0dd20000u, PROTO_AWS, 18}, /* 13.210.0.0/18 */
    {0x0dd24000u, PROTO_AWS, 23}, /* 13.210.64.0/23 */
    {0x0dd24200u, PROTO_AWS, 24}, /* 13.210.66.0/24 */
    {0x0dd24300u, PROTO_AWS, 25}, /* 13.210.67.0/25 */
    {0x0dd24380u, PROTO_CLOUDFRONT, 26}, /* 13.210.67.128/26 */
    {0x0dd243c0u, PROTO_AWS, 26}, /* 13.210.67.192/26 */
    {0x0dd24400u, PROTO_AWS, 22}, /* 13.210.68.0/22 */
    {0x0dd24800u, PROTO_AWS, 21}, /* 13.210.72.0/21 */
    {0x0dd25000u, PROTO_AWS, 20}, /* 13.210.80.0/20 */
    {0x0dd26000u, PROTO_AWS, 19}, /* 13.210.96.0/19 */
    {0x0dd28000u, PROTO_AWS, 17}, /* 13.210.128.0/17 */
    {0x0dd30000u, PROTO_AWS, 16}, /* 13.211.0.0/16 */
    {0x0dd40000u, PROTO_AWS, 14}, /* 13.212.0.0/14 */
    {0x0dd80000u, PROTO_AWS, 13}, /* 13.216.0.0/13 */
    {0x0de00000u, PROTO_CLOUDFRONT, 14}, /* 13.224.0.0/14 */
    {0x0de40000u, PROTO_AWS, 18}, /* 13.228.0.0/18 */
    {0x0de44000u, PROTO_AWS, 22}, /* 13.228.64.0/22 */
    {0x0de44400u, PROTO_AWS, 24}, /* 13.228.68.0/24 */
    {0x0de44500u, PROTO_CLOUDFRONT, 24}, /* 13.228.69.0/24 */
    {0x0de44600u, PROTO_AWS, 23}, /* 13.228.70.0/23 */
    {0x0de44800u, PROTO_AWS, 21}, /* 13.228.72.0/21 */
    {0x0de45000u, PROTO_AWS, 20}, /* 13.228.80.0/20 */
    {0x0de46000u, PROTO_AWS, 19}, /* 13.228.96.0/19 */
    {0x0de48000u, PROTO_AWS, 17}, /* 13.228.128.0/17 */
    {0x0de50000u, PROTO_AWS, 16}, /* 13.229.0.0/16 */
    {0x0de60000u, PROTO_AWS, 15}, /* 13.230.0.0/15 */
    {0x0de80000u, PROTO_AWS, 16}, /* 13.232.0.0/16 */
    {0x0de90000u, PROTO_AWS, 17}, /* 13.233.0.0/17 */
    {0x0de98000u, PROTO_AWS, 19}, /* 13.233.128.0/19 */
    {0x0de9a000u, PROTO_AWS, 20}, /* 13.233.160.0/20 */
    {0x0de9b000u, PROTO_AWS, 24}, /* 13.233.176.0/24 */
    {0x0de9b100u, PROTO_AWS, 25}, /* 13.233.177.0/25 */
    {0x0de9b180u, PROTO_AWS, 26}, /* 13.233.177.128/26 */
    {0x0de9b1c0u, PROTO_CLOUDFRONT, 26}, /* 13.233.177.192/26 */
    {0x0de9b200u, PROTO_AWS, 23}, /* 13.233.178.0/23 */
    {0x0de9b400u, PROTO_AWS, 22}, /* 13.233.180.0/22 */
    {0x0de9b800u, PROTO_AWS, 21}, /* 13.233.184.0/21 */
    {0x0de9c000u, PROTO_AWS, 18}, /* 13.233.192.0/18 */
    {0x0dea0000u, PROTO_AWS, 15}, /* 13.234.0.0/15 */
    {0x0dec0000u, PROTO_AWS, 14}, /* 13.236.0.0/14 */
    {0x0df00000u, PROTO_UNKNOWN, 0},
    {0x0df40000u, PROTO_AWS, 14}, /* 13.244.0.0/14 */
    {0x0df80000u, PROTO_AWS, 18}, /* 13.248.0.0/18 */
    {0x0df84000u, PROTO_AWS, 21}, /* 13.248.64.0/21 */
    {0x0df84800u, PROTO_AWS, 23}, /* 13.248.72.0/23 */
    {0x0df84a00u, PROTO_UNKNOWN, 0},
    {0x0df84b00u, PROTO_AWS, 24}, /* 13.248.75.0/24 */
    {0x0df84c00u, PROTO_AWS, 22}, /* 13.248.76.0/22 */
    {0x0df85000u, PROTO_AWS, 23}, /* 13.248.80.0/23 */
    {0x0df85200u, PROTO_AWS, 24}, /* 13.248.82.0/24 */
    {0x0df85300u, PROTO_UNKNOWN, 0},
    {0x0df86000u, PROTO_AWS, 19}, /* 13.248.96.0/19 */
    {0x0df88000u, PROTO_AWS, 17}, /* 13.248.128.0/17 */
    {0x0df90000u, PROTO_CLOUDFRONT, 16}, /* 13.249.0.0/16 */
    {0x0dfa0000u, PROTO_AWS, 15}, /* 13.250.0.0/15 */
    {0x0dfc0000u, PROTO_UNKNOWN, 0},
    {0x0e89e000u, PROTO_YAHOO, 19}, /* 14.137.224.0/19 */
    {0x0e8a0000u, PROTO_UNKNOWN, 0},
    {0x0f670000u, PROTO_AWS, 16}, /* 15.103.0.0/16 */
    {0x0f680000u, PROTO_UNKNOWN, 0},
    {0x0f800000u, PROTO_AWS, 16}, /* 15.128.0.0/16 */
    {0x0f810000u, PROTO_AWS, 18}, /* 15.129.0.0/18 */
    {0x0f814000u, PROTO_AWS, 20}, /* 15.129.64.0/20 */
    {0x0f815000u, PROTO_AWS, 22}, /* 15.129.80.0/22 */
    {0x0f815400u, PROTO_AWS, 23}, /* 15.129.84.0/23 */
    {0x0f815600u, PROTO_AWS, 24}, /* 15.129.86.0/24 */
    {0x0f815700u, PROTO_UNKNOWN, 0},
    {0x0f816000u, PROTO_AWS, 22}, /* 15.129.96.0/22 */
    {0x0f816400u, PROTO_UNKNOWN, 0},
    {0x0f860000u, PROTO_AWS, 15}, /* 15.134.0.0/15 */
    {0x0f880000u, PROTO_UNKNOWN, 0},
    {0x0f8f0000u, PROTO_AWS, 16}, /* 15.143.0.0/16 */
    {0x0f900000u, PROTO_UNKNOWN, 0},
    {0x0f910000u, PROTO_AWS, 22}, /* 15.145.0.0/22 */
    {0x0f910400u, PROTO_AWS, 23}, /* 15.145.4.0/23 */
    {0x0f910600u, PROTO_UNKNOWN, 0},
    {0x0f910800u, PROTO_AWS, 21}, /* 15.145.8.0/21 */
    {0x0f911800u, PROTO_AWS, 23}, /* 15.145.24.0/23 */
    {0x0f911a00u, PROTO_UNKNOWN, 0},
    {0x0f940000u, PROTO_AWS, 16}, /* 15.148.0.0/16 */
    {0x0f950000u, PROTO_UNKNOWN, 0},
    {0x0f980000u, PROTO_AWS, 16}, /* 15.152.0.0/16 */
    {0x0f990000u, PROTO_UNKNOWN, 0},
    {0x0f9c0000u, PROTO_AWS, 15}, /* 15.156.0.0/15 */
    {0x0f9e0000u, PROTO_CLOUDFRONT, 16}, /* 15.158.0.0/16 */
    {0x0f9f0000u, PROTO_AWS, 16}, /* 15.159.0.0/16 */
    {0x0fa00000u, PROTO_AWS, 15}, /* 15.160.0.0/15 */
    {0x0fa20000u, PROTO_UNKNOWN, 0},
    {0x0fa40000u, PROTO_AWS, 15}, /* 15.164.0.0/15 */
    {0x0fa60000u, PROTO_UNKNOWN, 0},
    {0x0fa80000u, PROTO_AWS, 16}, /* 15.168.0.0/16 */
    {0x0fa90000u, PROTO_UNKNOWN, 0},
    {0x0faf0000u, PROTO_AWS, 16}, /* 15.175.0.0/16 */
    {0x0fb00000u, PROTO_UNKNOWN, 0},
    {0x0fb10000u, PROTO_AWS, 18}, /* 15.177.0.0/18 */
    {0x0fb14000u, PROTO_AWS, 19}, /* 15.177.64.0/19 */
    {0x0fb16000u, PROTO_AWS, 22}, /* 15.177.96.0/22 */
    {0x0fb16400u, PROTO_AWS, 24}, /* 15.177.100.0/24 */
    {0x0fb16500u, PROTO_UNKNOWN, 0},
    {0x0fb16600u, PROTO_AWS, 23}, /* 15.177.102.0/23 */
    {0x0fb16800u, PROTO_AWS, 22}, /* 15.177.104.0/22 */
    {0x0fb16c00u, PROTO_AWS, 24}, /* 15.177.108.0/24 */
    {0x0fb16d00u, PROTO_UNKNOWN, 0},
    {0x0fb20000u, PROTO_AWS, 16}, /* 15.178.0.0/16 */
    {0x0fb30000u, PROTO_UNKNOWN, 0},
    {0x0fb50000u, PROTO_AWS, 17}, /* 15.181.0.0/17 */
    {0x0fb58000u, PROTO_AWS, 18}, /* 15.181.128.0/18 */
    {0x0fb5c000u, PROTO_AWS, 19}, /* 15.181.192.0/19 */
    {0x0fb5e000u, PROTO_AWS, 20}, /* 15.181.224.0/20 */
    {0x0fb5f000u, PROTO_AWS, 21}, /* 15.181.240.0/21 */
    {0x0fb5f800u, PROTO_AWS, 22}, /* 15.181.248.0/22 */
    {0x0fb5fc00u, PROTO_AWS, 23}, /* 15.181.252.0/23 */
    {0x0fb5fe00u, PROTO_AWS, 24}, /* 15.181.254.0/24 */
    {0x0fb5ff00u, PROTO_UNKNOWN, 0},
    {0x0fb80000u, PROTO_AWS, 15}, /* 15.184.0.0/15 */
    {0x0fba0000u, PROTO_UNKNOWN, 0},
    {0x0fbc0000u, PROTO_AWS, 17}, /* 15.188.0.0/17 */
    {0x0fbc8000u, PROTO_AWS, 19}, /* 15.188.128.0/19 */
    {0x0fbca000u, PROTO_AWS, 20}, /* 15.188.160.0/20 */
    {0x0fbcb000u, PROTO_AWS, 21}, /* 15.188.176.0/21 */
    {0x0fbcb800u, PROTO_CLOUDFRONT, 24}, /* 15.188.184.0/24 */
    {0x0fbcb900u, PROTO_AWS, 24}, /* 15.188.185.0/24 */
    {0x0fbcba00u, PROTO_AWS, 23}, /* 15.188.186.0/23 */
    {0x0fbcbc00u, PROTO_AWS, 22}, /* 15.188.188.0/22 */
    {0x0fbcc000u, PROTO_AWS, 18}, /* 15.188.192.0/18 */
    {0x0fbd0000u, PROTO_UNKNOWN, 0},
    {0x0fbe0000u, PROTO_AWS, 21}, /* 15.190.0.0/21 */
    {0x0fbe0800u, PROTO_AWS, 22}, /* 15.190.8.0/22 */
    {0x0fbe0c00u, PROTO_UNKNOWN, 0},
    {0x0fbe1000u, PROTO_AWS, 20}, /* 15.190.16.0/20 */
    {0x0fbe2000u, PROTO_AWS, 19}, /* 15.190.32.0/19 */
    {0x0fbe4000u, PROTO_UNKNOWN, 0},
    {0x0fbe5000u, PROTO_AWS, 20}, /* 15.190.80.0/20 */
    {0x0fbe6000u, PROTO_AWS, 19}, /* 15.190.96.0/19 */
    {0x0fbe8000u, PROTO_AWS, 18}, /* 15.190.128.0/18 */
    {0x0fbec000u, PROTO_UNKNOWN, 0},
    {0x0fbee000u, PROTO_AWS, 22}, /* 15.190.224.0/22 */
    {0x0fbee400u, PROTO_UNKNOWN, 0},
    {0x0fbee800u, PROTO_AWS, 21}, /* 15.190.232.0/21 */
    {0x0fbef000u, PROTO_AWS, 20}, /* 15.190.240.0/20 */
    {0x0fbf0000u, PROTO_UNKNOWN, 0},
    {0x0fc10000u, PROTO_AWS, 18}, /* 15.193.0.0/18 */
    {0x0fc14000u, PROTO_UNKNOWN, 0},
    {0x0fc18000u, PROTO_AWS, 19}, /* 15.193.128.0/19 */
    {0x0fc1a000u, PROTO_AWS, 20}, /* 15.193.160.0/20 */
    {0x0fc1b000u, PROTO_AWS, 22}, /* 15.193.176.0/22 */
    {0x0fc1b400u, PROTO_UNKNOWN, 0},
    {0x0fc50000u, PROTO_AWS, 19}, /* 15.197.0.0/19 */
    {0x0fc52000u, PROTO_AWS, 21}, /* 15.197.32.0/21 */
    {0x0fc52800u, PROTO_UNKNOWN, 0},
    {0x0fc54000u, PROTO_AWS, 19}, /* 15.197.64.0/19 */
    {0x0fc56000u, PROTO_UNKNOWN, 0},
    {0x0fc58000u, PROTO_AWS, 17}, /* 15.197.128.0/17 */
    {0x0fc60000u, PROTO_UNKNOWN, 0},
    {0x0fc80000u, PROTO_AWS, 16}, /* 15.200.0.0/16 */
    {0x0fc90000u, PROTO_UNKNOWN, 0},
    {0x0fc90100u, PROTO_AWS, 24}, /* 15.201.1.0/24 */
    {0x0fc90200u, PROTO_UNKNOWN, 0},
    {0x0fcd0000u, PROTO_AWS, 16}, /* 15.205.0.0/16 */
    {0x0fcf0000u, PROTO_AWS, 21}, /* 15.207.0.0/21 */
    {0x0fcf0800u, PROTO_AWS, 22}, /* 15.207.8.0/22 */
    {0x0fcf0c00u, PROTO_AWS, 24}, /* 15.207.12.0/24 */
    {0x0fcf0d00u, PROTO_AWS, 25}, /* 15.207.13.0/25 */
    {0x0fcf0d80u, PROTO_CLOUDFRONT, 25}, /* 15.207.13.128/25 */
    {0x0fcf0e00u, PROTO_AWS, 23}, /* 15.207.14.0/23 */
    {0x0fcf1000u, PROTO_AWS, 20}, /* 15.207.16.0/20 */
    {0x0fcf2000u, PROTO_AWS, 19}, /* 15.207.32.0/19 */
    {0x0fcf4000u, PROTO_AWS, 18}, /* 15.207.64.0/18 */
    {0x0fcfc000u, PROTO_AWS, 20}, /* 15.207.192.0/20 */
    {0x0fcfd000u, PROTO_AWS, 22}, /* 15.207.208.0/22 */
    {0x0fcfd400u, PROTO_AWS, 24}, /* 15.207.212.0/24 */
    {0x0fcfd500u, PROTO_AWS, 25}, /* 15.207.213.0/25 */
    {0x0fcfd580u, PROTO_CLOUDFRONT, 25}, /* 15.207.213.128/25 */
    {0x0fcfd600u, PROTO_AWS, 23}, /* 15.207.214.0/23 */
    {0x0fcfd800u, PROTO_AWS, 21}, /* 15.207.216.0/21 */
    {0x0fcfe000u, PROTO_AWS, 19}, /* 15.207.224.0/19 */
    {0x0fd00000u, PROTO_UNKNOWN, 0},
    {0x0fd80000u, PROTO_AWS, 15}, /* 15.216.0.0/15 */
    {0x0fda0000u, PROTO_UNKNOWN, 0},
    {0x0fdc0000u, PROTO_AWS, 19}, /* 15.220.0.0/19 */
    {0x0fdc2000u, PROTO_AWS, 21}, /* 15.220.32.0/21 */
    {0x0fdc2800u, PROTO_AWS, 22}, /* 15.220.40.0/22 */
    {0x0fdc2c00u, PROTO_UNKNOWN, 0},
    {0x0fdc3000u, PROTO_AWS, 20}, /* 15.220.48.0/20 */
    {0x0fdc4000u, PROTO_AWS, 19}, /* 15.220.64.0/19 */
    {0x0fdc6000u, PROTO_UNKNOWN, 0},
    {0x0fdc7000u, PROTO_AWS, 20}, /* 15.220.112.0/20 */
    {0x0fdc8000u, PROTO_AWS, 18}, /* 15.220.128.0/18 */
    {0x0fdcc000u, PROTO_AWS, 20}, /* 15.220.192.0/20 */
    {0x0fdcd000u, PROTO_UNKNOWN, 0},
    {0x0fdcd080u, PROTO_AWS, 26}, /* 15.220.208.128/26 */
    {0x0fdcd0c0u, PROTO_UNKNOWN, 0},
    {0x0fdcd800u, PROTO_AWS, 21}, /* 15.220.216.0/21 */
    {0x0fdce000u, PROTO_AWS, 19}, /* 15.220.224.0/19 */
    {0x0fdd2000u, PROTO_AWS, 20}, /* 15.221.32.0/20 */
    {0x0fdd3000u, PROTO_AWS, 22}, /* 15.221.48.0/22 */
    {0x0fdd3400u, PROTO_AWS, 23}, /* 15.221.52.0/23 */
    {0x0fdd3600u, PROTO_UNKNOWN, 0},
    {0x0fdd8000u, PROTO_AWS, 21}, /* 15.221.128.0/21 */
    {0x0fdd8800u, PROTO_UNKNOWN, 0},
    {0x0fdd9000u, PROTO_AWS, 21}, /* 15.221.144.0/21 */
    {0x0fdd9800u, PROTO_AWS, 23}, /* 15.221.152.0/23 */
    {0x0fdd9a00u, PROTO_UNKNOWN, 0},
    {0x0fdda000u, PROTO_AWS, 21}, /* 15.221.160.0/21 */
    {0x0fdda800u, PROTO_UNKNOWN, 0},
    {0x0fddb000u, PROTO_AWS, 20}, /* 15.221.176.0/20 */
    {0x0fddc000u, PROTO_UNKNOWN, 0},
    {0x0fde0000u, PROTO_AWS, 15}, /* 15.222.0.0/15 */
    {0x0fe20000u, PROTO_UNKNOWN, 0},
    {0x0fe30000u, PROTO_AWS, 16}, /* 15.227.0.0/16 */
    {0x0fe40000u, PROTO_AWS, 15}, /* 15.228.0.0/15 */
    {0x0fe60000u, PROTO_UNKNOWN, 0},
    {0x0fe60004u, PROTO_AWS, 30}, /* 15.230.0.4/30 */
    {0x0fe60008u, PROTO_AWS, 31}, /* 15.230.0.8/31 */
    {0x0fe6000au, PROTO_UNKNOWN, 0},
    {0x0fe6000cu, PROTO_AWS, 31}, /* 15.230.0.12/31 */
    {0x0fe6000eu, PROTO_AWS, 32}, /* 15.230.0.14/32 */
    {0x0fe6000fu, PROTO_UNKNOWN, 0},
    {0x0fe60100u, PROTO_AWS, 24}, /* 15.230.1.0/24 */
    {0x0fe60200u, PROTO_UNKNOWN, 0},
    {0x0fe60300u, PROTO_AWS, 24}, /* 15.230.3.0/24 */
    {0x0fe60400u, PROTO_UNKNOWN, 0},
    {0x0fe60411u, PROTO_AWS, 32}, /* 15.230.4.17/32 */
    {0x0fe60412u, PROTO_UNKNOWN, 0},
    {0x0fe60413u, PROTO_AWS, 32}, /* 15.230.4.19/32 */
    {0x0fe60414u, PROTO_UNKNOWN, 0},
    {0x0fe60480u, PROTO_AWS, 30}, /* 15.230.4.128/30 */
    {0x0fe60484u, PROTO_UNKNOWN, 0},
    {0x0fe60494u, PROTO_AWS, 30}, /* 15.230.4.148/30 */
    {0x0fe60498u, PROTO_AWS, 29}, /* 15.230.4.152/29 */
    {0x0fe604a8u, PROTO_UNKNOWN, 0},
    {0x0fe604b0u, PROTO_AWS, 28}, /* 15.230.4.176/28 */
    {0x0fe604c0u, PROTO_UNKNOWN, 0},
    {0x0fe60500u, PROTO_AWS, 24}, /* 15.230.5.0/24 */
    {0x0fe60700u, PROTO_UNKNOWN, 0},
    {0x0fe6090au, PROTO_AWS, 31}, /* 15.230.9.10/31 */
    {0x0fe6090cu, PROTO_AWS, 30}, /* 15.230.9.12/30 */
    {0x0fe60910u, PROTO_UNKNOWN, 0},
    {0x0fe6092cu, PROTO_AWS, 30}, /* 15.230.9.44/30 */
    {0x0fe60930u, PROTO_UNKNOWN, 0},
    {0x0fe609f8u, PROTO_AWS, 32}, /* 15.230.9.248/32 */
    {0x0fe609f9u, PROTO_UNKNOWN, 0},
    {0x0fe609fcu, PROTO_AWS, 31}, /* 15.230.9.252/31 */
    {0x0fe609feu, PROTO_UNKNOWN, 0},
    {0x0fe60a00u, PROTO_AWS, 24}, /* 15.230.10.0/24 */
    {0x0fe60b00u, PROTO_UNKNOWN, 0},
    {0x0fe60e00u, PROTO_AWS, 24}, /* 15.230.14.0/24 */
    {0x0fe60f00u, PROTO_AWS, 32}, /* 15.230.15.0/32 */
    {0x0fe60f01u, PROTO_UNKNOWN, 0},
    {0x0fe60f03u, PROTO_AWS, 32}, /* 15.230.15.3/32 */
    {0x0fe60f04u, PROTO_AWS, 30}, /* 15.230.15.4/30 */
    {0x0fe60f0cu, PROTO_UNKNOWN, 0},
    {0x0fe60f0du, PROTO_AWS, 32}, /* 15.230.15.13/32 */
    {0x0fe60f0eu, PROTO_AWS, 31}, /* 15.230.15.14/31 */
    {0x0fe60f10u, PROTO_AWS, 32}, /* 15.230.15.16/32 */
    {0x0fe60f11u, PROTO_UNKNOWN, 0},
    {0x0fe60f18u, PROTO_AWS, 29}, /* 15.230.15.24/29 */
    {0x0fe60f20u, PROTO_AWS, 27}, /* 15.230.15.32/27 */
    {0x0fe60f40u, PROTO_AWS, 26}, /* 15.230.15.64/26 */
    {0x0fe60fc0u, PROTO_AWS, 30}, /* 15.230.15.192/30 */
    {0x0fe60fc4u, PROTO_UNKNOWN, 0},
    {0x0fe60fc8u, PROTO_AWS, 29}, /* 15.230.15.200/29 */
    {0x0fe60fd8u, PROTO_AWS, 30}, /* 15.230.15.216/30 */
    {0x0fe60fdcu, PROTO_UNKNOWN, 0},
    {0x0fe60ffeu, PROTO_AWS, 31}, /* 15.230.15.254/31 */
    {0x0fe61000u, PROTO_AWS, 24}, /* 15.230.16.0/24 */
    {0x0fe61100u, PROTO_UNKNOWN, 0},
    {0x0fe61200u, PROTO_AWS, 23}, /* 15.230.18.0/23 */
    {0x0fe61400u, PROTO_UNKNOWN, 0},
    {0x0fe61500u, PROTO_AWS, 24}, /* 15.230.21.0/24 */
    {0x0fe61600u, PROTO_AWS, 23}, /* 15.230.22.0/23 */
    {0x0fe61800u, PROTO_AWS, 21}, /* 15.230.24.0/21 */
    {0x0fe62000u, PROTO_AWS, 24}, /* 15.230.32.0/24 */
    {0x0fe62100u, PROTO_UNKNOWN, 0},
    {0x0fe62300u, PROTO_AWS, 24}, /* 15.230.35.0/24 */
    {0x0fe62400u, PROTO_AWS, 22}, /* 15.230.36.0/22 */
    {0x0fe62c00u, PROTO_UNKNOWN, 0},
    {0x0fe63000u, PROTO_AWS, 21}, /* 15.230.48.0/21 */
    {0x0fe63800u, PROTO_AWS, 22}, /* 15.230.56.0/22 */
    {0x0fe63c00u, PROTO_AWS, 23}, /* 15.230.60.0/23 */
    {0x0fe63e00u, PROTO_AWS, 24}, /* 15.230.62.0/24 */
    {0x0fe63f00u, PROTO_AWS, 30}, /* 15.230.63.0/30 */
    {0x0fe63f04u, PROTO_AWS, 31}, /* 15.230.63.4/31 */
    {0x0fe63f06u, PROTO_AWS, 32}, /* 15.230.63.6/32 */
    {0x0fe63f07u, PROTO_UNKNOWN, 0},
    {0x0fe63f08u, PROTO_AWS, 30}, /* 15.230.63.8/30 */
    {0x0fe63f0cu, PROTO_UNKNOWN, 0},
    {0x0fe64000u, PROTO_AWS, 21}, /* 15.230.64.0/21 */
    {0x0fe64800u, PROTO_AWS, 22}, /* 15.230.72.0/22 */
    {0x0fe64c00u, PROTO_AWS, 23}, /* 15.230.76.0/23 */
    {0x0fe64e00u, PROTO_AWS, 24}, /* 15.230.78.0/24 */
    {0x0fe64f00u, PROTO_AWS, 25}, /* 15.230.79.0/25 */
    {0x0fe64f80u, PROTO_AWS, 26}, /* 15.230.79.128/26 */
    {0x0fe64fc0u, PROTO_UNKNOWN, 0},
    {0x0fe65000u, PROTO_AWS, 20}, /* 15.230.80.0/20 */
    {0x0fe66000u, PROTO_AWS, 22}, /* 15.230.96.0/22 */
    {0x0fe66400u, PROTO_AWS, 31}, /* 15.230.100.0/31 */
    {0x0fe66402u, PROTO_AWS, 32}, /* 15.230.100.2/32 */
    {0x0fe66403u, PROTO_UNKNOWN, 0},
    {0x0fe66500u, PROTO_AWS, 24}, /* 15.230.101.0/24 */
    {0x0fe66600u, PROTO_AWS, 23}, /* 15.230.102.0/23 */
    {0x0fe66a00u, PROTO_AWS, 24}, /* 15.230.106.0/24 */
    {0x0fe66b00u, PROTO_AWS, 32}, /* 15.230.107.0/32 */
    {0x0fe66b01u, PROTO_UNKNOWN, 0},
    {0x0fe66b02u, PROTO_AWS, 31}, /* 15.230.107.2/31 */
    {0x0fe66b04u, PROTO_UNKNOWN, 0},
    {0x0fe66c00u, PROTO_AWS, 22}, /* 15.230.108.0/22 */
    {0x0fe67400u, PROTO_AWS, 24}, /* 15.230.116.0/24 */
    {0x0fe67500u, PROTO_AWS, 31}, /* 15.230.117.0/31 */
    {0x0fe67502u, PROTO_UNKNOWN, 0},
    {0x0fe67600u, PROTO_AWS, 24}, /* 15.230.118.0/24 */
    {0x0fe67700u, PROTO_AWS, 31}, /* 15.230.119.0/31 */
    {0x0fe67702u, PROTO_UNKNOWN, 0},
    {0x0fe67800u, PROTO_AWS, 31}, /* 15.230.120.0/31 */
    {0x0fe67802u, PROTO_UNKNOWN, 0},
    {0x0fe67900u, PROTO_AWS, 29}, /* 15.230.121.0/29 */
    {0x0fe67908u, PROTO_AWS, 31}, /* 15.230.121.8/31 */
    {0x0fe6790au, PROTO_UNKNOWN, 0},
    {0x0fe67a00u, PROTO_AWS, 29}, /* 15.230.122.0/29 */
    {0x0fe67a08u, PROTO_UNKNOWN, 0},
    {0x0fe67b00u, PROTO_AWS, 24}, /* 15.230.123.0/24 */
    {0x0fe67d00u, PROTO_UNKNOWN, 0},
    {0x0fe68100u, PROTO_AWS, 24}, /* 15.230.129.0/24 */
    {0x0fe68200u, PROTO_AWS, 23}, /* 15.230.130.0/23 */
    {0x0fe68400u, PROTO_AWS, 22}, /* 15.230.132.0/22 */
    {0x0fe68800u, PROTO_AWS, 23}, /* 15.230.136.0/23 */
    {0x0fe68a00u, PROTO_AWS, 24}, /* 15.230.138.0/24 */
    {0x0fe68b00u, PROTO_UNKNOWN, 0},
    {0x0fe68c00u, PROTO_AWS, 22}, /* 15.230.140.0/22 */
    {0x0fe69000u, PROTO_AWS, 23}, /* 15.230.144.0/23 */
    {0x0fe69200u, PROTO_UNKNOWN, 0},
    {0x0fe69300u, PROTO_AWS, 24}, /* 15.230.147.0/24 */
    {0x0fe69500u, PROTO_AWS, 30}, /* 15.230.149.0/30 */
    {0x0fe69504u, PROTO_AWS, 31}, /* 15.230.149.4/31 */
    {0x0fe69506u, PROTO_UNKNOWN, 0},
    {0x0fe69508u, PROTO_AWS, 30}, /* 15.230.149.8/30 */
    {0x0fe6950cu, PROTO_UNKNOWN, 0},
    {0x0fe69600u, PROTO_AWS, 23}, /* 15.230.150.0/23 */
    {0x0fe69800u, PROTO_AWS, 21}, /* 15.230.152.0/21 */
    {0x0fe6a800u, PROTO_AWS, 24}, /* 15.230.168.0/24 */
    {0x0fe6a900u, PROTO_AWS, 29}, /* 15.230.169.0/29 */
    {0x0fe6a908u, PROTO_UNKNOWN, 0},
    {0x0fe6aa00u, PROTO_AWS, 23}, /* 15.230.170.0/23 */
    {0x0fe6ac00u, PROTO_UNKNOWN, 0},
    {0x0fe6ad00u, PROTO_AWS, 24}, /* 15.230.173.0/24 */
    {0x0fe6af00u, PROTO_UNKNOWN, 0},
    {0x0fe6b000u, PROTO_AWS, 23}, /* 15.230.176.0/23 */
    {0x0fe6b200u, PROTO_AWS, 24}, /* 15.230.178.0/24 */
    {0x0fe6b300u, PROTO_AWS, 28}, /* 15.230.179.0/28 */
    {0x0fe6b310u, PROTO_AWS, 29}, /* 15.230.179.16/29 */
    {0x0fe6b318u, PROTO_UNKNOWN, 0},
    {0x0fe6b400u, PROTO_AWS, 22}, /* 15.230.180.0/22 */
    {0x0fe6bc00u, PROTO_AWS, 23}, /* 15.230.188.0/23 */
    {0x0fe6be00u, PROTO_AWS, 24}, /* 15.230.190.0/24 */
    {0x0fe6bf00u, PROTO_UNKNOWN, 0},
    {0x0fe6c000u, PROTO_AWS, 22}, /* 15.230.192.0/22 */
    {0x0fe6c400u, PROTO_AWS, 23}, /* 15.230.196.0/23 */
    {0x0fe6c600u, PROTO_AWS, 24}, /* 15.230.198.0/24 */
    {0x0fe6c700u, PROTO_AWS, 28}, /* 15.230.199.0/28 */
    {0x0fe6c710u, PROTO_UNKNOWN, 0},
    {0x0fe6c800u, PROTO_AWS, 23}, /* 15.230.200.0/23 */
    {0x0fe6ca00u, PROTO_AWS, 30}, /* 15.230.202.0/30 */
    {0x0fe6ca04u, PROTO_UNKNOWN, 0},
    {0x0fe6cb00u, PROTO_AWS, 24}, /* 15.230.203.0/24 */
    {0x0fe6cc00u, PROTO_AWS, 25}, /* 15.230.204.0/25 */
    {0x0fe6cc80u, PROTO_UNKNOWN, 0},
    {0x0fe6cd00u, PROTO_AWS, 24}, /* 15.230.205.0/24 */
    {0x0fe6ce00u, PROTO_AWS, 23}, /* 15.230.206.0/23 */
    {0x0fe6d000u, PROTO_AWS, 21}, /* 15.230.208.0/21 */
    {0x0fe6d800u, PROTO_AWS, 29}, /* 15.230.216.0/29 */
    {0x0fe6d808u, PROTO_AWS, 30}, /* 15.230.216.8/30 */
    {0x0fe6d80cu, PROTO_AWS, 31}, /* 15.230.216.12/31 */
    {0x0fe6d80eu, PROTO_UNKNOWN, 0},
    {0x0fe6d900u, PROTO_AWS, 24}, /* 15.230.217.0/24 */
    {0x0fe6da00u, PROTO_AWS, 23}, /* 15.230.218.0/23 */
    {0x0fe6de00u, PROTO_AWS, 24}, /* 15.230.222.0/24 */
    {0x0fe6df00u, PROTO_AWS, 28}, /* 15.230.223.0/28 */
    {0x0fe6df10u, PROTO_UNKNOWN, 0},
    {0x0fe6f000u, PROTO_AWS, 21}, /* 15.230.240.0/21 */
    {0x0fe6f800u, PROTO_AWS, 23}, /* 15.230.248.0/23 */
    {0x0fe6fa00u, PROTO_AWS, 24}, /* 15.230.250.0/24 */
    {0x0fe6fb00u, PROTO_AWS, 29}, /* 15.230.251.0/29 */
    {0x0fe6fb08u, PROTO_UNKNOWN, 0},
    {0x0fe6fc00u, PROTO_AWS, 23}, /* 15.230.252.0/23 */
    {0x0fe6fe00u, PROTO_AWS, 30}, /* 15.230.254.0/30 */
    {0x0fe6fe04u, PROTO_AWS, 32}, /* 15.230.254.4/32 */
    {0x0fe6fe05u, PROTO_UNKNOWN, 0},
    {0x0fe6ff00u, PROTO_AWS, 24}, /* 15.230.255.0/24 */
    {0x0fe70000u, PROTO_UNKNOWN, 0},
    {0x0fe80000u, PROTO_AWS, 15}, /* 15.232.0.0/15 */
    {0x0fea0000u, PROTO_UNKNOWN, 0},
    {0x0fec0000u, PROTO_AWS, 15}, /* 15.236.0.0/15 */
    {0x0fee0000u, PROTO_UNKNOWN, 0},
    {0x0ff00000u, PROTO_AWS, 15}, /* 15.240.0.0/15 */
    {0x0ff20000u, PROTO_UNKNOWN, 0},
    {0x0ff80800u, PROTO_AWS, 22}, /* 15.248.8.0/22 */
    {0x0ff80c00u, PROTO_UNKNOWN, 0},
    {0x0ff81000u, PROTO_AWS, 20}, /* 15.248.16.0/20 */
    {0x0ff82000u, PROTO_AWS, 21}, /* 15.248.32.0/21 */
    {0x0ff82800u, PROTO_AWS, 22}, /* 15.248.40.0/22 */
    {0x0ff82c00u, PROTO_UNKNOWN, 0},
    {0x0ff83000u, PROTO_AWS, 20}, /* 15.248.48.0/20 */
    {0x0ff84000u, PROTO_AWS, 21}, /* 15.248.64.0/21 */
    {0x0ff84800u, PROTO_UNKNOWN, 0},
    {0x0ff85000u, PROTO_AWS, 20}, /* 15.248.80.0/20 */
    {0x0ff86000u, PROTO_UNKNOWN, 0},
    {0x0ff86800u, PROTO_AWS, 24}, /* 15.248.104.0/24 */
    {0x0ff86900u, PROTO_UNKNOWN, 0},
    {0x0ff86a00u, PROTO_AWS, 23}, /* 15.248.106.0/23 */
    {0x0ff86c00u, PROTO_UNKNOWN, 0},
    {0x0ff87000u, PROTO_AWS, 20}, /* 15.248.112.0/20 */
    {0x0ff88000u, PROTO_AWS, 19}, /* 15.248.128.0/19 */
    {0x0ff8a000u, PROTO_AWS, 23}, /* 15.248.160.0/23 */
    {0x0ff8a200u, PROTO_AWS, 24}, /* 15.248.162.0/24 */
    {0x0ff8a300u, PROTO_UNKNOWN, 0},
    {0x0ff8a301u, PROTO_AWS, 32}, /* 15.248.163.1/32 */
    {0x0ff8a302u, PROTO_UNKNOWN, 0},
    {0x0ff8a400u, PROTO_AWS, 23}, /* 15.248.164.0/23 */
    {0x0ff8a600u, PROTO_UNKNOWN, 0},
    {0x0ff8a700u, PROTO_AWS, 28}, /* 15.248.167.0/28 */
    {0x0ff8a710u, PROTO_AWS, 29}, /* 15.248.167.16/29 */
    {0x0ff8a718u, PROTO_UNKNOWN, 0},
    {0x0ff8a800u, PROTO_AWS, 21}, /* 15.248.168.0/21 */
    {0x0ff8b000u, PROTO_AWS, 20}, /* 15.248.176.0/20 */
    {0x0ff8c000u, PROTO_UNKNOWN, 0},
    {0x0ff8c100u, PROTO_AWS, 31}, /* 15.248.193.0/31 */
    {0x0ff8c102u, PROTO_UNKNOWN, 0},
    {0x0ff8c200u, PROTO_AWS, 23}, /* 15.248.194.0/23 */
    {0x0ff8c400u, PROTO_UNKNOWN, 0},
    {0x0ff90000u, PROTO_AWS, 16}, /* 15.249.0.0/16 */
    {0x0ffa0000u, PROTO_UNKNOWN, 0},
    {0x0ffb0000u, PROTO_AWS, 28}, /* 15.251.0.0/28 */
    {0x0ffb0010u, PROTO_UNKNOWN, 0},
    {0x0ffb0014u, PROTO_AWS, 30}, /* 15.251.0.20/30 */
    {0x0ffb001cu, PROTO_AWS, 31}, /* 15.251.0.28/31 */
    {0x0ffb001eu, PROTO_UNKNOWN, 0},
    {0x0ffb0021u, PROTO_AWS, 32}, /* 15.251.0.33/32 */
    {0x0ffb0023u, PROTO_UNKNOWN, 0},
    {0x0ffb002fu, PROTO_AWS, 32}, /* 15.251.0.47/32 */
    {0x0ffb0031u, PROTO_UNKNOWN, 0},
    {0x0ffc0000u, PROTO_AWS, 15}, /* 15.252.0.0/15 */
    {0x0ffe0000u, PROTO_AWS, 16}, /* 15.254.0.0/16 */
    {0x0fff0000u, PROTO_UNKNOWN, 0},
    {0x10040000u, PROTO_AWS, 16}, /* 16.4.0.0/16 */
    {0x10050000u, PROTO_UNKNOWN, 0},
    {0x10060000u, PROTO_AWS, 16}, /* 16.6.0.0/16 */
    {0x10070000u, PROTO_UNKNOWN, 0},
    {0x100b0000u, PROTO_AWS, 16}, /* 16.11.0.0/16 */
    {0x100c0000u, PROTO_AWS, 20}, /* 16.12.0.0/20 */
    {0x100c1000u, PROTO_AWS, 22}, /* 16.12.16.0/22 */
    {0x100c1400u, PROTO_AWS, 23}, /* 16.12.20.0/23 */
    {0x100c1600u, PROTO_UNKNOWN, 0},
    {0x100c1800u, PROTO_AWS, 21}, /* 16.12.24.0/21 */
    {0x100c2800u, PROTO_AWS, 22}, /* 16.12.40.0/22 */
    {0x100c2c00u, PROTO_AWS, 24}, /* 16.12.44.0/24 */
    {0x100c2d00u, PROTO_UNKNOWN, 0},
    {0x100c3000u, PROTO_AWS, 20}, /* 16.12.48.0/20 */
    {0x100c4000u, PROTO_AWS, 22}, /* 16.12.64.0/22 */
    {0x100c4400u, PROTO_UNKNOWN, 0},
    {0x100c4700u, PROTO_AWS, 24}, /* 16.12.71.0/24 */
    {0x100c4800u, PROTO_AWS, 21}, /* 16.12.72.0/21 */
    {0x100c5000u, PROTO_AWS, 22}, /* 16.12.80.0/22 */
    {0x100c5400u, PROTO_AWS, 23}, /* 16.12.84.0/23 */
    {0x100c5600u, PROTO_AWS, 24}, /* 16.12.86.0/24 */
    {0x100c5700u, PROTO_UNKNOWN, 0},
    {0x100c5800u, PROTO_AWS, 21}, /* 16.12.88.0/21 */
    {0x100c6000u, PROTO_AWS, 20}, /* 16.12.96.0/20 */
    {0x100c7000u, PROTO_AWS, 21}, /* 16.12.112.0/21 */
    {0x100c7800u, PROTO_AWS, 22}, /* 16.12.120.0/22 */
    {0x100c7c00u, PROTO_UNKNOWN, 0},
    {0x100f0000u, PROTO_AWS, 18}, /* 16.15.0.0/18 */
    {0x100f4000u, PROTO_AWS, 19}, /* 16.15.64.0/19 */
    {0x100f6000u, PROTO_AWS, 20}, /* 16.15.96.0/20 */
    {0x100f7000u, PROTO_AWS, 21}, /* 16.15.112.0/21 */
    {0x100f7800u, PROTO_AWS, 22}, /* 16.15.120.0/22 */
    {0x100f7c00u, PROTO_UNKNOWN, 0},
    {0x100f9c00u, PROTO_AWS, 22}, /* 16.15.156.0/22 */
    {0x100fa000u, PROTO_AWS, 19}, /* 16.15.160.0/19 */
    {0x100fc000u, PROTO_AWS, 18}, /* 16.15.192.0/18 */
    {0x10100000u, PROTO_AWS, 16}, /* 16.16.0.0/16 */
    {0x10110000u, PROTO_UNKNOWN, 0},
    {0x10120000u, PROTO_AWS, 15}, /* 16.18.0.0/15 */
    {0x10140000u, PROTO_UNKNOWN, 0},
    {0x10160000u, PROTO_AWS, 15}, /* 16.22.0.0/15 */
    {0x10180000u, PROTO_AWS, 13}, /* 16.24.0.0/13 */
    {0x10200000u, PROTO_UNKNOWN, 0},
    {0x10300000u, PROTO_AWS, 13}, /* 16.48.0.0/13 */
    {0x10380000u, PROTO_AWS, 16}, /* 16.56.0.0/16 */
    {0x10390000u, PROTO_AWS, 18}, /* 16.57.0.0/18 */
    {0x10394000u, PROTO_UNKNOWN, 0},
    {0x103a0000u, PROTO_AWS, 15}, /* 16.58.0.0/15 */
    {0x103c0000u, PROTO_AWS, 14}, /* 16.60.0.0/14 */
    {0x10400000u, PROTO_AWS, 17}, /* 16.64.0.0/17 */
    {0x10408000u, PROTO_UNKNOWN, 0},
    {0x10410000u, PROTO_AWS, 16}, /* 16.65.0.0/16 */
    {0x10420000u, PROTO_AWS, 15}, /* 16.66.0.0/15 */
    {0x10440000u, PROTO_UNKNOWN, 0},
    {0x10470000u, PROTO_AWS, 17}, /* 16.71.0.0/17 */
    {0x10478000u, PROTO_UNKNOWN, 0},
    {0x104c0000u, PROTO_AWS, 14}, /* 16.76.0.0/14 */
    {0x10500000u, PROTO_UNKNOWN, 0},
    {0x106a0000u, PROTO_AWS, 15}, /* 16.106.0.0/15 */
    {0x106c0000u, PROTO_UNKNOWN, 0},
    {0x10700000u, PROTO_AWS, 15}, /* 16.112.0.0/15 */
    {0x10720000u, PROTO_UNKNOWN, 0},
    {0x108c0000u, PROTO_AWS, 15}, /* 16.140.0.0/15 */
    {0x108e0000u, PROTO_UNKNOWN, 0},
    {0x10900000u, PROTO_AWS, 12}, /* 16.144.0.0/12 */
    {0x10a00000u, PROTO_UNKNOWN, 0},
    {0x10a20000u, PROTO_AWS, 15}, /* 16.162.0.0/15 */
    {0x10a60000u, PROTO_UNKNOWN, 0},
    {0x10a80000u, PROTO_AWS, 14}, /* 16.168.0.0/14 */
    {0x10ac0000u, PROTO_UNKNOWN, 0},
    {0x10ae0000u, PROTO_AWS, 15}, /* 16.174.0.0/15 */
    {0x10b00000u, PROTO_AWS, 14}, /* 16.176.0.0/14 */
    {0x10b40000u, PROTO_AWS, 15}, /* 16.180.0.0/15 */
    {0x10b60000u, PROTO_AWS, 16}, /* 16.182.0.0/16 */
    {0x10b70000u, PROTO_UNKNOWN, 0},
    {0x10b80000u, PROTO_AWS, 14}, /* 16.184.0.0/14 */
    {0x10bc0000u, PROTO_AWS, 15}, /* 16.188.0.0/15 */
    {0x10be0000u, PROTO_UNKNOWN, 0},
    {0x10c00000u, PROTO_AWS, 13}, /* 16.192.0.0/13 */
    {0x10c80000u, PROTO_UNKNOWN, 0},
    {0x10ce0000u, PROTO_AWS, 15}, /* 16.206.0.0/15 */
    {0x10d20000u, PROTO_UNKNOWN, 0},
    {0x10d60000u, PROTO_AWS, 21}, /* 16.214.0.0/21 */
    {0x10d60800u, PROTO_AWS, 22}, /* 16.214.8.0/22 */
    {0x10d60c00u, PROTO_UNKNOWN, 0},
    {0x10d61000u, PROTO_AWS, 20}, /* 16.214.16.0/20 */
    {0x10d63000u, PROTO_AWS, 21}, /* 16.214.48.0/21 */
    {0x10d63800u, PROTO_AWS, 22}, /* 16.214.56.0/22 */
    {0x10d63c00u, PROTO_UNKNOWN, 0},
    {0x11000000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11004000u, PROTO_APPLE, 18}, /* 17.0.64.0/18 */
    {0x1100c000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11014000u, PROTO_APPLE, 18}, /* 17.1.64.0/18 */
    {0x1101c000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11100000u, PROTO_APPLE, 12}, /* 17.16.0.0/12 */
    {0x11104000u, PROTO_APPLE, 21}, /* 17.16.64.0/21 */
    {0x11104800u, PROTO_APPLE, 12}, /* 17.16.0.0/12 */
    {0x11184000u, PROTO_APPLE, 21}, /* 17.24.64.0/21 */
    {0x11184800u, PROTO_APPLE, 12}, /* 17.16.0.0/12 */
    {0x111b0000u, PROTO_APPLE, 16}, /* 17.27.0.0/16 */
    {0x111c0000u, PROTO_APPLE, 12}, /* 17.16.0.0/12 */
    {0x111f0000u, PROTO_APPLE, 16}, /* 17.31.0.0/16 */
    {0x11200000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11220000u, PROTO_APPLE, 16}, /* 17.34.0.0/16 */
    {0x11230000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11240000u, PROTO_APPLE, 15}, /* 17.36.0.0/15 */
    {0x11260000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x112c0000u, PROTO_APPLE, 15}, /* 17.44.0.0/15 */
    {0x112d0000u, PROTO_APPLE, 16}, /* 17.45.0.0/16 */
    {0x112d1400u, PROTO_APPLE, 23}, /* 17.45.20.0/23 */
    {0x112d2200u, PROTO_APPLE, 16}, /* 17.45.0.0/16 */
    {0x112d2400u, PROTO_APPLE, 22}, /* 17.45.36.0/22 */
    {0x112d2800u, PROTO_APPLE, 16}, /* 17.45.0.0/16 */
    {0x112d3000u, PROTO_APPLE, 21}, /* 17.45.48.0/21 */
    {0x112d4000u, PROTO_APPLE, 16}, /* 17.45.0.0/16 */
    {0x112d7000u, PROTO_APPLE, 20}, /* 17.45.112.0/20 */
    {0x112d8000u, PROTO_APPLE, 23}, /* 17.45.128.0/23 */
    {0x112d8c00u, PROTO_APPLE, 16}, /* 17.45.0.0/16 */
    {0x112d9000u, PROTO_APPLE, 22}, /* 17.45.144.0/22 */
    {0x112d9400u, PROTO_APPLE, 16}, /* 17.45.0.0/16 */
    {0x112d9800u, PROTO_APPLE, 22}, /* 17.45.152.0/22 */
    {0x112da000u, PROTO_APPLE, 21}, /* 17.45.160.0/21 */
    {0x112dd000u, PROTO_APPLE, 16}, /* 17.45.0.0/16 */
    {0x112df000u, PROTO_APPLE, 20}, /* 17.45.240.0/20 */
    {0x112e0000u, PROTO_APPLE, 16}, /* 17.46.0.0/16 */
    {0x112f0000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11320000u, PROTO_APPLE, 16}, /* 17.50.0.0/16 */
    {0x11330000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11400000u, PROTO_APPLE, 16}, /* 17.64.0.0/16 */
    {0x11420000u, PROTO_APPLE, 17}, /* 17.66.0.0/17 */
    {0x11427400u, PROTO_APPLE, 22}, /* 17.66.116.0/22 */
    {0x11427800u, PROTO_APPLE, 17}, /* 17.66.0.0/17 */
    {0x11428000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11430000u, PROTO_APPLE, 16}, /* 17.67.0.0/16 */
    {0x11435000u, PROTO_APPLE, 20}, /* 17.67.80.0/20 */
    {0x11436000u, PROTO_APPLE, 16}, /* 17.67.0.0/16 */
    {0x11436800u, PROTO_APPLE, 21}, /* 17.67.104.0/21 */
    {0x11437000u, PROTO_APPLE, 16}, /* 17.67.0.0/16 */
    {0x11437800u, PROTO_APPLE, 22}, /* 17.67.120.0/22 */
    {0x11437c00u, PROTO_APPLE, 16}, /* 17.67.0.0/16 */
    {0x11438000u, PROTO_APPLE, 18}, /* 17.67.128.0/18 */
    {0x1143c000u, PROTO_APPLE, 22}, /* 17.67.192.0/22 */
    {0x1143c400u, PROTO_APPLE, 23}, /* 17.67.196.0/23 */
    {0x1143c800u, PROTO_APPLE, 22}, /* 17.67.200.0/22 */
    {0x1143d800u, PROTO_APPLE, 21}, /* 17.67.216.0/21 */
    {0x1143e000u, PROTO_APPLE, 20}, /* 17.67.224.0/20 */
    {0x1143e800u, PROTO_APPLE, 22}, /* 17.67.232.0/22 */
    {0x11440000u, PROTO_APPLE, 16}, /* 17.68.0.0/16 */
    {0x11450400u, PROTO_APPLE, 22}, /* 17.69.4.0/22 */
    {0x11450a00u, PROTO_APPLE, 23}, /* 17.69.10.0/23 */
    {0x11450c00u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x11451000u, PROTO_APPLE, 22}, /* 17.69.16.0/22 */
    {0x11451800u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x11452000u, PROTO_APPLE, 22}, /* 17.69.32.0/22 */
    {0x11452100u, PROTO_APPLE, 24}, /* 17.69.33.0/24 */
    {0x11452400u, PROTO_APPLE, 22}, /* 17.69.36.0/22 */
    {0x11453000u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x11453800u, PROTO_APPLE, 22}, /* 17.69.56.0/22 */
    {0x11454000u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x11456400u, PROTO_APPLE, 22}, /* 17.69.100.0/22 */
    {0x11456c00u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x11457000u, PROTO_APPLE, 22}, /* 17.69.112.0/22 */
    {0x11457800u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x11459c00u, PROTO_APPLE, 22}, /* 17.69.156.0/22 */
    {0x1145a800u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x1145c000u, PROTO_APPLE, 20}, /* 17.69.192.0/20 */
    {0x1145d000u, PROTO_APPLE, 21}, /* 17.69.208.0/21 */
    {0x1145d800u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x1145e000u, PROTO_APPLE, 21}, /* 17.69.224.0/21 */
    {0x1145ec00u, PROTO_APPLE, 22}, /* 17.69.236.0/22 */
    {0x1145f000u, PROTO_APPLE, 21}, /* 17.69.240.0/21 */
    {0x1145f800u, PROTO_APPLE, 16}, /* 17.69.0.0/16 */
    {0x11466400u, PROTO_APPLE, 22}, /* 17.70.100.0/22 */
    {0x11466800u, PROTO_APPLE, 16}, /* 17.70.0.0/16 */
    {0x11484000u, PROTO_APPLE, 19}, /* 17.72.64.0/19 */
    {0x11488000u, PROTO_APPLE, 16}, /* 17.72.0.0/16 */
    {0x11498000u, PROTO_APPLE, 17}, /* 17.73.128.0/17 */
    {0x114a0000u, PROTO_APPLE, 16}, /* 17.74.0.0/16 */
    {0x114adc00u, PROTO_APPLE, 22}, /* 17.74.220.0/22 */
    {0x114ae400u, PROTO_APPLE, 16}, /* 17.74.0.0/16 */
    {0x114b0000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x114c0000u, PROTO_APPLE, 16}, /* 17.76.0.0/16 */
    {0x114c1400u, PROTO_APPLE, 22}, /* 17.76.20.0/22 */
    {0x114c1c00u, PROTO_APPLE, 16}, /* 17.76.0.0/16 */
    {0x114c3000u, PROTO_APPLE, 22}, /* 17.76.48.0/22 */
    {0x114c3400u, PROTO_APPLE, 16}, /* 17.76.0.0/16 */
    {0x114d1400u, PROTO_APPLE, 23}, /* 17.77.20.0/23 */
    {0x114d1600u, PROTO_APPLE, 16}, /* 17.77.0.0/16 */
    {0x114d2000u, PROTO_APPLE, 22}, /* 17.77.32.0/22 */
    {0x114d2400u, PROTO_APPLE, 16}, /* 17.77.0.0/16 */
    {0x114d3000u, PROTO_APPLE, 22}, /* 17.77.48.0/22 */
    {0x114d3400u, PROTO_APPLE, 16}, /* 17.77.0.0/16 */
    {0x114d3800u, PROTO_APPLE, 22}, /* 17.77.56.0/22 */
    {0x114d3c00u, PROTO_APPLE, 16}, /* 17.77.0.0/16 */
    {0x114d4000u, PROTO_APPLE, 21}, /* 17.77.64.0/21 */
    {0x114d4800u, PROTO_APPLE, 16}, /* 17.77.0.0/16 */
    {0x114d5000u, PROTO_APPLE, 21}, /* 17.77.80.0/21 */
    {0x114d6000u, PROTO_APPLE, 16}, /* 17.77.0.0/16 */
    {0x114d8000u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114d8400u, PROTO_APPLE, 23}, /* 17.77.132.0/23 */
    {0x114d8500u, PROTO_APPLE, 24}, /* 17.77.133.0/24 */
    {0x114d8600u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114d8800u, PROTO_APPLE, 23}, /* 17.77.136.0/23 */
    {0x114d8a00u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114d8c00u, PROTO_APPLE, 23}, /* 17.77.140.0/23 */
    {0x114d9000u, PROTO_APPLE, 22}, /* 17.77.144.0/22 */
    {0x114d9400u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114d9800u, PROTO_APPLE, 22}, /* 17.77.152.0/22 */
    {0x114d9c00u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114da000u, PROTO_APPLE, 22}, /* 17.77.160.0/22 */
    {0x114da400u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114da800u, PROTO_APPLE, 22}, /* 17.77.168.0/22 */
    {0x114dac00u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114db000u, PROTO_APPLE, 21}, /* 17.77.176.0/21 */
    {0x114db800u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114dc000u, PROTO_APPLE, 21}, /* 17.77.192.0/21 */
    {0x114dc800u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114dd000u, PROTO_APPLE, 21}, /* 17.77.208.0/21 */
    {0x114dd800u, PROTO_APPLE, 17}, /* 17.77.128.0/17 */
    {0x114df000u, PROTO_APPLE, 20}, /* 17.77.240.0/20 */
    {0x114e0000u, PROTO_APPLE, 16}, /* 17.78.0.0/16 */
    {0x114e2000u, PROTO_APPLE, 21}, /* 17.78.32.0/21 */
    {0x114e2800u, PROTO_APPLE, 16}, /* 17.78.0.0/16 */
    {0x114e7c00u, PROTO_APPLE, 22}, /* 17.78.124.0/22 */
    {0x114e8000u, PROTO_APPLE, 21}, /* 17.78.128.0/21 */
    {0x114e8800u, PROTO_APPLE, 16}, /* 17.78.0.0/16 */
    {0x114e8a00u, PROTO_APPLE, 23}, /* 17.78.138.0/23 */
    {0x114e8b00u, PROTO_APPLE, 24}, /* 17.78.139.0/24 */
    {0x114e8c00u, PROTO_APPLE, 22}, /* 17.78.140.0/22 */
    {0x114e9000u, PROTO_APPLE, 21}, /* 17.78.144.0/21 */
    {0x114e9800u, PROTO_APPLE, 16}, /* 17.78.0.0/16 */
    {0x114ec000u, PROTO_APPLE, 20}, /* 17.78.192.0/20 */
    {0x114ec800u, PROTO_APPLE, 23}, /* 17.78.200.0/23 */
    {0x114eca00u, PROTO_APPLE, 20}, /* 17.78.192.0/20 */
    {0x114ed000u, PROTO_APPLE, 21}, /* 17.78.208.0/21 */
    {0x114ed800u, PROTO_APPLE, 16}, /* 17.78.0.0/16 */
    {0x114ee000u, PROTO_APPLE, 20}, /* 17.78.224.0/20 */
    {0x114ee800u, PROTO_APPLE, 23}, /* 17.78.232.0/23 */
    {0x114eea00u, PROTO_APPLE, 20}, /* 17.78.224.0/20 */
    {0x114ef000u, PROTO_APPLE, 16}, /* 17.78.0.0/16 */
    {0x114f0800u, PROTO_APPLE, 22}, /* 17.79.8.0/22 */
    {0x114f0c00u, PROTO_APPLE, 16}, /* 17.79.0.0/16 */
    {0x11538000u, PROTO_APPLE, 17}, /* 17.83.128.0/17 */
    {0x11540000u, PROTO_APPLE, 16}, /* 17.84.0.0/16 */
    {0x1154c600u, PROTO_APPLE, 24}, /* 17.84.198.0/24 */
    {0x1154c700u, PROTO_APPLE, 16}, /* 17.84.0.0/16 */
    {0x11560000u, PROTO_APPLE, 17}, /* 17.86.0.0/17 */
    {0x11560100u, PROTO_APPLE, 24}, /* 17.86.1.0/24 */
    {0x11560200u, PROTO_APPLE, 23}, /* 17.86.2.0/23 */
    {0x11560300u, PROTO_APPLE, 24}, /* 17.86.3.0/24 */
    {0x11560400u, PROTO_APPLE, 22}, /* 17.86.4.0/22 */
    {0x11560500u, PROTO_APPLE, 24}, /* 17.86.5.0/24 */
    {0x11560600u, PROTO_APPLE, 23}, /* 17.86.6.0/23 */
    {0x11560700u, PROTO_APPLE, 24}, /* 17.86.7.0/24 */
    {0x11560800u, PROTO_APPLE, 21}, /* 17.86.8.0/21 */
    {0x11560900u, PROTO_APPLE, 24}, /* 17.86.9.0/24 */
    {0x11560a00u, PROTO_APPLE, 23}, /* 17.86.10.0/23 */
    {0x11560b00u, PROTO_APPLE, 24}, /* 17.86.11.0/24 */
    {0x11560c00u, PROTO_APPLE, 22}, /* 17.86.12.0/22 */
    {0x11560d00u, PROTO_APPLE, 24}, /* 17.86.13.0/24 */
    {0x11560e00u, PROTO_APPLE, 23}, /* 17.86.14.0/23 */
    {0x11560f00u, PROTO_APPLE, 24}, /* 17.86.15.0/24 */
    {0x11561000u, PROTO_APPLE, 20}, /* 17.86.16.0/20 */
    {0x11561100u, PROTO_APPLE, 24}, /* 17.86.17.0/24 */
    {0x11561200u, PROTO_APPLE, 23}, /* 17.86.18.0/23 */
    {0x11561300u, PROTO_APPLE, 24}, /* 17.86.19.0/24 */
    {0x11561400u, PROTO_APPLE, 22}, /* 17.86.20.0/22 */
    {0x11561500u, PROTO_APPLE, 24}, /* 17.86.21.0/24 */
    {0x11561600u, PROTO_APPLE, 23}, /* 17.86.22.0/23 */
    {0x11561700u, PROTO_APPLE, 24}, /* 17.86.23.0/24 */
    {0x11561800u, PROTO_APPLE, 21}, /* 17.86.24.0/21 */
    {0x11561900u, PROTO_APPLE, 24}, /* 17.86.25.0/24 */
    {0x11561a00u, PROTO_APPLE, 23}, /* 17.86.26.0/23 */
    {0x11561b00u, PROTO_APPLE, 24}, /* 17.86.27.0/24 */
    {0x11561c00u, PROTO_APPLE, 22}, /* 17.86.28.0/22 */
    {0x11561d00u, PROTO_APPLE, 24}, /* 17.86.29.0/24 */
    {0x11561e00u, PROTO_APPLE, 23}, /* 17.86.30.0/23 */
    {0x11561f00u, PROTO_APPLE, 24}, /* 17.86.31.0/24 */
    {0x11562000u, PROTO_APPLE, 19}, /* 17.86.32.0/19 */
    {0x11562100u, PROTO_APPLE, 24}, /* 17.86.33.0/24 */
    {0x11562200u, PROTO_APPLE, 23}, /* 17.86.34.0/23 */
    {0x11562300u, PROTO_APPLE, 24}, /* 17.86.35.0/24 */
    {0x11562400u, PROTO_APPLE, 22}, /* 17.86.36.0/22 */
    {0x11562500u, PROTO_APPLE, 24}, /* 17.86.37.0/24 */
    {0x11562600u, PROTO_APPLE, 23}, /* 17.86.38.0/23 */
    {0x11562700u, PROTO_APPLE, 24}, /* 17.86.39.0/24 */
    {0x11562800u, PROTO_APPLE, 21}, /* 17.86.40.0/21 */
    {0x11562900u, PROTO_APPLE, 24}, /* 17.86.41.0/24 */
    {0x11562a00u, PROTO_APPLE, 23}, /* 17.86.42.0/23 */
    {0x11562b00u, PROTO_APPLE, 24}, /* 17.86.43.0/24 */
    {0x11562c00u, PROTO_APPLE, 22}, /* 17.86.44.0/22 */
    {0x11562d00u, PROTO_APPLE, 24}, /* 17.86.45.0/24 */
    {0x11562e00u, PROTO_APPLE, 23}, /* 17.86.46.0/23 */
    {0x11562f00u, PROTO_APPLE, 24}, /* 17.86.47.0/24 */
    {0x11563000u, PROTO_APPLE, 20}, /* 17.86.48.0/20 */
    {0x11563100u, PROTO_APPLE, 24}, /* 17.86.49.0/24 */
    {0x11563200u, PROTO_APPLE, 23}, /* 17.86.50.0/23 */
    {0x11563300u, PROTO_APPLE, 24}, /* 17.86.51.0/24 */
    {0x11563400u, PROTO_APPLE, 22}, /* 17.86.52.0/22 */
    {0x11563500u, PROTO_APPLE, 24}, /* 17.86.53.0/24 */
    {0x11563600u, PROTO_APPLE, 23}, /* 17.86.54.0/23 */
    {0x11563700u, PROTO_APPLE, 24}, /* 17.86.55.0/24 */
    {0x11563800u, PROTO_APPLE, 21}, /* 17.86.56.0/21 */
    {0x11563900u, PROTO_APPLE, 24}, /* 17.86.57.0/24 */
    {0x11563a00u, PROTO_APPLE, 23}, /* 17.86.58.0/23 */
    {0x11563b00u, PROTO_APPLE, 24}, /* 17.86.59.0/24 */
    {0x11563c00u, PROTO_APPLE, 22}, /* 17.86.60.0/22 */
    {0x11563d00u, PROTO_APPLE, 24}, /* 17.86.61.0/24 */
    {0x11563e00u, PROTO_APPLE, 23}, /* 17.86.62.0/23 */
    {0x11563f00u, PROTO_APPLE, 24}, /* 17.86.63.0/24 */
    {0x11564000u, PROTO_APPLE, 18}, /* 17.86.64.0/18 */
    {0x11564100u, PROTO_APPLE, 24}, /* 17.86.65.0/24 */
    {0x11564200u, PROTO_APPLE, 23}, /* 17.86.66.0/23 */
    {0x11564300u, PROTO_APPLE, 24}, /* 17.86.67.0/24 */
    {0x11564400u, PROTO_APPLE, 22}, /* 17.86.68.0/22 */
    {0x11564500u, PROTO_APPLE, 24}, /* 17.86.69.0/24 */
    {0x11564600u, PROTO_APPLE, 23}, /* 17.86.70.0/23 */
    {0x11564700u, PROTO_APPLE, 24}, /* 17.86.71.0/24 */
    {0x11564800u, PROTO_APPLE, 21}, /* 17.86.72.0/21 */
    {0x11564900u, PROTO_APPLE, 24}, /* 17.86.73.0/24 */
    {0x11564a00u, PROTO_APPLE, 23}, /* 17.86.74.0/23 */
    {0x11564b00u, PROTO_APPLE, 24}, /* 17.86.75.0/24 */
    {0x11564c00u, PROTO_APPLE, 22}, /* 17.86.76.0/22 */
    {0x11564d00u, PROTO_APPLE, 24}, /* 17.86.77.0/24 */
    {0x11564e00u, PROTO_APPLE, 23}, /* 17.86.78.0/23 */
    {0x11564f00u, PROTO_APPLE, 24}, /* 17.86.79.0/24 */
    {0x11565000u, PROTO_APPLE, 20}, /* 17.86.80.0/20 */
    {0x11565100u, PROTO_APPLE, 24}, /* 17.86.81.0/24 */
    {0x11565200u, PROTO_APPLE, 23}, /* 17.86.82.0/23 */
    {0x11565300u, PROTO_APPLE, 24}, /* 17.86.83.0/24 */
    {0x11565400u, PROTO_APPLE, 22}, /* 17.86.84.0/22 */
    {0x11565500u, PROTO_APPLE, 24}, /* 17.86.85.0/24 */
    {0x11565600u, PROTO_APPLE, 23}, /* 17.86.86.0/23 */
    {0x11565700u, PROTO_APPLE, 24}, /* 17.86.87.0/24 */
    {0x11565800u, PROTO_APPLE, 21}, /* 17.86.88.0/21 */
    {0x11565900u, PROTO_APPLE, 24}, /* 17.86.89.0/24 */
    {0x11565a00u, PROTO_APPLE, 23}, /* 17.86.90.0/23 */
    {0x11565b00u, PROTO_APPLE, 24}, /* 17.86.91.0/24 */
    {0x11565c00u, PROTO_APPLE, 22}, /* 17.86.92.0/22 */
    {0x11565d00u, PROTO_APPLE, 24}, /* 17.86.93.0/24 */
    {0x11565e00u, PROTO_APPLE, 23}, /* 17.86.94.0/23 */
    {0x11565f00u, PROTO_APPLE, 24}, /* 17.86.95.0/24 */
    {0x11566000u, PROTO_APPLE, 19}, /* 17.86.96.0/19 */
    {0x11566100u, PROTO_APPLE, 24}, /* 17.86.97.0/24 */
    {0x11566200u, PROTO_APPLE, 23}, /* 17.86.98.0/23 */
    {0x11566300u, PROTO_APPLE, 24}, /* 17.86.99.0/24 */
    {0x11566400u, PROTO_APPLE, 22}, /* 17.86.100.0/22 */
    {0x11566500u, PROTO_APPLE, 24}, /* 17.86.101.0/24 */
    {0x11566600u, PROTO_APPLE, 23}, /* 17.86.102.0/23 */
    {0x11566700u, PROTO_APPLE, 24}, /* 17.86.103.0/24 */
    {0x11566800u, PROTO_APPLE, 21}, /* 17.86.104.0/21 */
    {0x11566900u, PROTO_APPLE, 24}, /* 17.86.105.0/24 */
    {0x11566a00u, PROTO_APPLE, 23}, /* 17.86.106.0/23 */
    {0x11566b00u, PROTO_APPLE, 24}, /* 17.86.107.0/24 */
    {0x11566c00u, PROTO_APPLE, 22}, /* 17.86.108.0/22 */
    {0x11566d00u, PROTO_APPLE, 24}, /* 17.86.109.0/24 */
    {0x11566e00u, PROTO_APPLE, 23}, /* 17.86.110.0/23 */
    {0x11566f00u, PROTO_APPLE, 24}, /* 17.86.111.0/24 */
    {0x11567000u, PROTO_APPLE, 20}, /* 17.86.112.0/20 */
    {0x11567100u, PROTO_APPLE, 24}, /* 17.86.113.0/24 */
    {0x11567200u, PROTO_APPLE, 23}, /* 17.86.114.0/23 */
    {0x11567300u, PROTO_APPLE, 24}, /* 17.86.115.0/24 */
    {0x11567400u, PROTO_APPLE, 22}, /* 17.86.116.0/22 */
    {0x11567500u, PROTO_APPLE, 24}, /* 17.86.117.0/24 */
    {0x11567600u, PROTO_APPLE, 23}, /* 17.86.118.0/23 */
    {0x11567700u, PROTO_APPLE, 24}, /* 17.86.119.0/24 */
    {0x11567800u, PROTO_APPLE, 21}, /* 17.86.120.0/21 */
    {0x11567900u, PROTO_APPLE, 24}, /* 17.86.121.0/24 */
    {0x11567a00u, PROTO_APPLE, 23}, /* 17.86.122.0/23 */
    {0x11567b00u, PROTO_APPLE, 24}, /* 17.86.123.0/24 */
    {0x11567c00u, PROTO_APPLE, 22}, /* 17.86.124.0/22 */
    {0x11567d00u, PROTO_APPLE, 24}, /* 17.86.125.0/24 */
    {0x11567e00u, PROTO_APPLE, 23}, /* 17.86.126.0/23 */
    {0x11567f00u, PROTO_APPLE, 24}, /* 17.86.127.0/24 */
    {0x11568000u, PROTO_APPLE, 17}, /* 17.86.128.0/17 */
    {0x11568100u, PROTO_APPLE, 24}, /* 17.86.129.0/24 */
    {0x11568200u, PROTO_APPLE, 23}, /* 17.86.130.0/23 */
    {0x11568300u, PROTO_APPLE, 24}, /* 17.86.131.0/24 */
    {0x11568400u, PROTO_APPLE, 23}, /* 17.86.132.0/23 */
    {0x11568500u, PROTO_APPLE, 24}, /* 17.86.133.0/24 */
    {0x11568600u, PROTO_APPLE, 23}, /* 17.86.134.0/23 */
    {0x11568700u, PROTO_APPLE, 24}, /* 17.86.135.0/24 */
    {0x11568800u, PROTO_APPLE, 21}, /* 17.86.136.0/21 */
    {0x11568900u, PROTO_APPLE, 24}, /* 17.86.137.0/24 */
    {0x11568a00u, PROTO_APPLE, 23}, /* 17.86.138.0/23 */
    {0x11568b00u, PROTO_APPLE, 24}, /* 17.86.139.0/24 */
    {0x11568c00u, PROTO_APPLE, 22}, /* 17.86.140.0/22 */
    {0x11568d00u, PROTO_APPLE, 24}, /* 17.86.141.0/24 */
    {0x11568e00u, PROTO_APPLE, 23}, /* 17.86.142.0/23 */
    {0x11568f00u, PROTO_APPLE, 24}, /* 17.86.143.0/24 */
    {0x11569000u, PROTO_APPLE, 20}, /* 17.86.144.0/20 */
    {0x11569100u, PROTO_APPLE, 24}, /* 17.86.145.0/24 */
    {0x11569200u, PROTO_APPLE, 23}, /* 17.86.146.0/23 */
    {0x11569300u, PROTO_APPLE, 24}, /* 17.86.147.0/24 */
    {0x11569400u, PROTO_APPLE, 22}, /* 17.86.148.0/22 */
    {0x11569500u, PROTO_APPLE, 24}, /* 17.86.149.0/24 */
    {0x11569600u, PROTO_APPLE, 23}, /* 17.86.150.0/23 */
    {0x11569700u, PROTO_APPLE, 24}, /* 17.86.151.0/24 */
    {0x11569800u, PROTO_APPLE, 21}, /* 17.86.152.0/21 */
    {0x11569900u, PROTO_APPLE, 24}, /* 17.86.153.0/24 */
    {0x11569a00u, PROTO_APPLE, 23}, /* 17.86.154.0/23 */
    {0x11569b00u, PROTO_APPLE, 24}, /* 17.86.155.0/24 */
    {0x11569c00u, PROTO_APPLE, 22}, /* 17.86.156.0/22 */
    {0x11569d00u, PROTO_APPLE, 24}, /* 17.86.157.0/24 */
    {0x11569e00u, PROTO_APPLE, 23}, /* 17.86.158.0/23 */
    {0x11569f00u, PROTO_APPLE, 24}, /* 17.86.159.0/24 */
    {0x1156a000u, PROTO_APPLE, 19}, /* 17.86.160.0/19 */
    {0x1156a100u, PROTO_APPLE, 24}, /* 17.86.161.0/24 */
    {0x1156a200u, PROTO_APPLE, 23}, /* 17.86.162.0/23 */
    {0x1156a300u, PROTO_APPLE, 24}, /* 17.86.163.0/24 */
    {0x1156a400u, PROTO_APPLE, 22}, /* 17.86.164.0/22 */
    {0x1156a500u, PROTO_APPLE, 24}, /* 17.86.165.0/24 */
    {0x1156a600u, PROTO_APPLE, 23}, /* 17.86.166.0/23 */
    {0x1156a700u, PROTO_APPLE, 24}, /* 17.86.167.0/24 */
    {0x1156a800u, PROTO_APPLE, 21}, /* 17.86.168.0/21 */
    {0x1156a900u, PROTO_APPLE, 24}, /* 17.86.169.0/24 */
    {0x1156aa00u, PROTO_APPLE, 23}, /* 17.86.170.0/23 */
    {0x1156ab00u, PROTO_APPLE, 24}, /* 17.86.171.0/24 */
    {0x1156ac00u, PROTO_APPLE, 22}, /* 17.86.172.0/22 */
    {0x1156ad00u, PROTO_APPLE, 24}, /* 17.86.173.0/24 */
    {0x1156ae00u, PROTO_APPLE, 23}, /* 17.86.174.0/23 */
    {0x1156af00u, PROTO_APPLE, 24}, /* 17.86.175.0/24 */
    {0x1156b000u, PROTO_APPLE, 20}, /* 17.86.176.0/20 */
    {0x1156b100u, PROTO_APPLE, 24}, /* 17.86.177.0/24 */
    {0x1156b200u, PROTO_APPLE, 23}, /* 17.86.178.0/23 */
    {0x1156b300u, PROTO_APPLE, 24}, /* 17.86.179.0/24 */
    {0x1156b400u, PROTO_APPLE, 22}, /* 17.86.180.0/22 */
    {0x1156b500u, PROTO_APPLE, 24}, /* 17.86.181.0/24 */
    {0x1156b600u, PROTO_APPLE, 23}, /* 17.86.182.0/23 */
    {0x1156b700u, PROTO_APPLE, 24}, /* 17.86.183.0/24 */
    {0x1156b800u, PROTO_APPLE, 21}, /* 17.86.184.0/21 */
    {0x1156b900u, PROTO_APPLE, 24}, /* 17.86.185.0/24 */
    {0x1156ba00u, PROTO_APPLE, 23}, /* 17.86.186.0/23 */
    {0x1156bb00u, PROTO_APPLE, 24}, /* 17.86.187.0/24 */
    {0x1156bc00u, PROTO_APPLE, 22}, /* 17.86.188.0/22 */
    {0x1156bd00u, PROTO_APPLE, 24}, /* 17.86.189.0/24 */
    {0x1156be00u, PROTO_APPLE, 23}, /* 17.86.190.0/23 */
    {0x1156bf00u, PROTO_APPLE, 24}, /* 17.86.191.0/24 */
    {0x1156c000u, PROTO_APPLE, 18}, /* 17.86.192.0/18 */
    {0x1156c100u, PROTO_APPLE, 24}, /* 17.86.193.0/24 */
    {0x1156c200u, PROTO_APPLE, 23}, /* 17.86.194.0/23 */
    {0x1156c300u, PROTO_APPLE, 24}, /* 17.86.195.0/24 */
    {0x1156c400u, PROTO_APPLE, 22}, /* 17.86.196.0/22 */
    {0x1156c500u, PROTO_APPLE, 24}, /* 17.86.197.0/24 */
    {0x1156c600u, PROTO_APPLE, 23}, /* 17.86.198.0/23 */
    {0x1156c700u, PROTO_APPLE, 24}, /* 17.86.199.0/24 */
    {0x1156c800u, PROTO_APPLE, 21}, /* 17.86.200.0/21 */
    {0x1156c900u, PROTO_APPLE, 24}, /* 17.86.201.0/24 */
    {0x1156ca00u, PROTO_APPLE, 23}, /* 17.86.202.0/23 */
    {0x1156cb00u, PROTO_APPLE, 24}, /* 17.86.203.0/24 */
    {0x1156cc00u, PROTO_APPLE, 22}, /* 17.86.204.0/22 */
    {0x1156cd00u, PROTO_APPLE, 24}, /* 17.86.205.0/24 */
    {0x1156ce00u, PROTO_APPLE, 23}, /* 17.86.206.0/23 */
    {0x1156cf00u, PROTO_APPLE, 24}, /* 17.86.207.0/24 */
    {0x1156d000u, PROTO_APPLE, 20}, /* 17.86.208.0/20 */
    {0x1156d100u, PROTO_APPLE, 24}, /* 17.86.209.0/24 */
    {0x1156d200u, PROTO_APPLE, 23}, /* 17.86.210.0/23 */
    {0x1156d300u, PROTO_APPLE, 24}, /* 17.86.211.0/24 */
    {0x1156d400u, PROTO_APPLE, 22}, /* 17.86.212.0/22 */
    {0x1156d500u, PROTO_APPLE, 24}, /* 17.86.213.0/24 */
    {0x1156d600u, PROTO_APPLE, 23}, /* 17.86.214.0/23 */
    {0x1156d700u, PROTO_APPLE, 24}, /* 17.86.215.0/24 */
    {0x1156d800u, PROTO_APPLE, 21}, /* 17.86.216.0/21 */
    {0x1156d900u, PROTO_APPLE, 24}, /* 17.86.217.0/24 */
    {0x1156da00u, PROTO_APPLE, 23}, /* 17.86.218.0/23 */
    {0x1156db00u, PROTO_APPLE, 24}, /* 17.86.219.0/24 */
    {0x1156dc00u, PROTO_APPLE, 22}, /* 17.86.220.0/22 */
    {0x1156dd00u, PROTO_APPLE, 24}, /* 17.86.221.0/24 */
    {0x1156de00u, PROTO_APPLE, 23}, /* 17.86.222.0/23 */
    {0x1156df00u, PROTO_APPLE, 24}, /* 17.86.223.0/24 */
    {0x1156e000u, PROTO_APPLE, 19}, /* 17.86.224.0/19 */
    {0x1156e100u, PROTO_APPLE, 24}, /* 17.86.225.0/24 */
    {0x1156e200u, PROTO_APPLE, 23}, /* 17.86.226.0/23 */
    {0x1156e300u, PROTO_APPLE, 24}, /* 17.86.227.0/24 */
    {0x1156e400u, PROTO_APPLE, 22}, /* 17.86.228.0/22 */
    {0x1156e500u, PROTO_APPLE, 24}, /* 17.86.229.0/24 */
    {0x1156e600u, PROTO_APPLE, 23}, /* 17.86.230.0/23 */
    {0x1156e700u, PROTO_APPLE, 24}, /* 17.86.231.0/24 */
    {0x1156e800u, PROTO_APPLE, 21}, /* 17.86.232.0/21 */
    {0x1156e900u, PROTO_APPLE, 24}, /* 17.86.233.0/24 */
    {0x1156ea00u, PROTO_APPLE, 23}, /* 17.86.234.0/23 */
    {0x1156eb00u, PROTO_APPLE, 24}, /* 17.86.235.0/24 */
    {0x1156ec00u, PROTO_APPLE, 22}, /* 17.86.236.0/22 */
    {0x1156ed00u, PROTO_APPLE, 24}, /* 17.86.237.0/24 */
    {0x1156ee00u, PROTO_APPLE, 23}, /* 17.86.238.0/23 */
    {0x1156ef00u, PROTO_APPLE, 24}, /* 17.86.239.0/24 */
    {0x1156f000u, PROTO_APPLE, 20}, /* 17.86.240.0/20 */
    {0x1156f100u, PROTO_APPLE, 24}, /* 17.86.241.0/24 */
    {0x1156f200u, PROTO_APPLE, 23}, /* 17.86.242.0/23 */
    {0x1156f300u, PROTO_APPLE, 24}, /* 17.86.243.0/24 */
    {0x1156f400u, PROTO_APPLE, 22}, /* 17.86.244.0/22 */
    {0x1156f500u, PROTO_APPLE, 24}, /* 17.86.245.0/24 */
    {0x1156f600u, PROTO_APPLE, 23}, /* 17.86.246.0/23 */
    {0x1156f700u, PROTO_APPLE, 24}, /* 17.86.247.0/24 */
    {0x1156f800u, PROTO_APPLE, 21}, /* 17.86.248.0/21 */
    {0x1156f900u, PROTO_APPLE, 24}, /* 17.86.249.0/24 */
    {0x1156fa00u, PROTO_APPLE, 23}, /* 17.86.250.0/23 */
    {0x1156fb00u, PROTO_APPLE, 24}, /* 17.86.251.0/24 */
    {0x1156fc00u, PROTO_APPLE, 22}, /* 17.86.252.0/22 */
    {0x1156fd00u, PROTO_APPLE, 24}, /* 17.86.253.0/24 */
    {0x1156fe00u, PROTO_APPLE, 23}, /* 17.86.254.0/23 */
    {0x1156ff00u, PROTO_APPLE, 24}, /* 17.86.255.0/24 */
    {0x11570000u, PROTO_APPLE, 16}, /* 17.87.0.0/16 */
    {0x11590000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x115a0000u, PROTO_APPLE, 15}, /* 17.90.0.0/15 */
    {0x115c0000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x115e0000u, PROTO_APPLE, 16}, /* 17.94.0.0/16 */
    {0x115f0000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11660000u, PROTO_APPLE, 16}, /* 17.102.0.0/16 */
    {0x11690000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x116a0000u, PROTO_APPLE, 15}, /* 17.106.0.0/15 */
    {0x116c0000u, PROTO_APPLE, 16}, /* 17.108.0.0/16 */
    {0x116e0000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x11700000u, PROTO_APPLE, 16}, /* 17.112.0.0/16 */
    {0x11708000u, PROTO_APPLE, 17}, /* 17.112.128.0/17 */
    {0x11708c00u, PROTO_APPLE, 24}, /* 17.112.140.0/24 */
    {0x11708d00u, PROTO_APPLE, 17}, /* 17.112.128.0/17 */
    {0x11710000u, PROTO_APPLE, 16}, /* 17.113.0.0/16 */
    {0x11720000u, PROTO_APPLE, 15}, /* 17.114.0.0/15 */
    {0x11740000u, PROTO_APPLE, 16}, /* 17.116.0.0/16 */
    {0x11750000u, PROTO_APPLE, 9}, /* 17.0.0.0/9 */
    {0x117e0000u, PROTO_APPLE, 15}, /* 17.126.0.0/15 */
    {0x117f4000u, PROTO_APPLE, 20}, /* 17.127.64.0/20 */
    {0x117f5000u, PROTO_APPLE, 15}, /* 17.126.0.0/15 */
    {0x11800000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11806400u, PROTO_APPLE, 22}, /* 17.128.100.0/22 */
    {0x11806800u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11806a00u, PROTO_APPLE, 23}, /* 17.128.106.0/23 */
    {0x11806c00u, PROTO_APPLE, 22}, /* 17.128.108.0/22 */
    {0x11807400u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11807c00u, PROTO_APPLE, 23}, /* 17.128.124.0/23 */
    {0x11807e00u, PROTO_APPLE, 24}, /* 17.128.126.0/24 */
    {0x11807f00u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11820000u, PROTO_APPLE, 17}, /* 17.130.0.0/17 */
    {0x11828000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11840000u, PROTO_APPLE, 17}, /* 17.132.0.0/17 */
    {0x11842000u, PROTO_APPLE, 19}, /* 17.132.32.0/19 */
    {0x11844000u, PROTO_APPLE, 18}, /* 17.132.64.0/18 */
    {0x11848000u, PROTO_APPLE, 17}, /* 17.132.128.0/17 */
    {0x1184c000u, PROTO_APPLE, 18}, /* 17.132.192.0/18 */
    {0x11850000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11860000u, PROTO_APPLE, 17}, /* 17.134.0.0/17 */
    {0x11868000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11870000u, PROTO_APPLE, 16}, /* 17.135.0.0/16 */
    {0x11880000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11900000u, PROTO_APPLE, 16}, /* 17.144.0.0/16 */
    {0x11910000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11920000u, PROTO_APPLE, 16}, /* 17.146.0.0/16 */
    {0x11940000u, PROTO_APPLE, 14}, /* 17.148.0.0/14 */
    {0x11980000u, PROTO_APPLE, 16}, /* 17.152.0.0/16 */
    {0x119b0000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x119e0000u, PROTO_APPLE, 15}, /* 17.158.0.0/15 */
    {0x11a00000u, PROTO_APPLE, 12}, /* 17.160.0.0/12 */
    {0x11a40000u, PROTO_APPLE, 14}, /* 17.164.0.0/14 */
    {0x11a80000u, PROTO_APPLE, 13}, /* 17.168.0.0/13 */
    {0x11ab3f00u, PROTO_APPLE, 24}, /* 17.171.63.0/24 */
    {0x11ab4000u, PROTO_APPLE, 13}, /* 17.168.0.0/13 */
    {0x11b00000u, PROTO_APPLE, 15}, /* 17.176.0.0/15 */
    {0x11b20000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11b40000u, PROTO_APPLE, 14}, /* 17.180.0.0/14 */
    {0x11b80000u, PROTO_APPLE, 16}, /* 17.184.0.0/16 */
    {0x11ba0000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11bb0000u, PROTO_APPLE, 24}, /* 17.187.0.0/24 */
    {0x11bb0100u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11c10c00u, PROTO_APPLE, 22}, /* 17.193.12.0/22 */
    {0x11c11000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11c30c00u, PROTO_APPLE, 22}, /* 17.195.12.0/22 */
    {0x11c31000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11c36000u, PROTO_APPLE, 21}, /* 17.195.96.0/21 */
    {0x11c36800u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11c50000u, PROTO_APPLE, 16}, /* 17.197.0.0/16 */
    {0x11c60000u, PROTO_APPLE, 15}, /* 17.198.0.0/15 */
    {0x11c80000u, PROTO_APPLE, 14}, /* 17.200.0.0/14 */
    {0x11c90000u, PROTO_APPLE, 16}, /* 17.201.0.0/16 */
    {0x11cc0000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11cf0000u, PROTO_APPLE, 16}, /* 17.207.0.0/16 */
    {0x11d00000u, PROTO_APPLE, 15}, /* 17.208.0.0/15 */
    {0x11d20000u, PROTO_APPLE, 17}, /* 17.210.0.0/17 */
    {0x11d24000u, PROTO_APPLE, 18}, /* 17.210.64.0/18 */
    {0x11d28000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11d30000u, PROTO_APPLE, 19}, /* 17.211.0.0/19 */
    {0x11d32000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11d40000u, PROTO_APPLE, 14}, /* 17.212.0.0/14 */
    {0x11d80000u, PROTO_APPLE, 16}, /* 17.216.0.0/16 */
    {0x11d90000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11db6400u, PROTO_APPLE, 22}, /* 17.219.100.0/22 */
    {0x11db6800u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11e00000u, PROTO_APPLE, 14}, /* 17.224.0.0/14 */
    {0x11e40000u, PROTO_APPLE, 15}, /* 17.228.0.0/15 */
    {0x11e60000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11e80000u, PROTO_APPLE, 16}, /* 17.232.0.0/16 */
    {0x11ea0000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11eb8000u, PROTO_APPLE, 20}, /* 17.235.128.0/20 */
    {0x11eb9000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11ebc000u, PROTO_APPLE, 20}, /* 17.235.192.0/20 */
    {0x11ec0000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11ee0000u, PROTO_APPLE, 15}, /* 17.238.0.0/15 */
    {0x11ef0000u, PROTO_APPLE, 16}, /* 17.239.0.0/16 */
    {0x11f20000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11f40000u, PROTO_APPLE, 14}, /* 17.244.0.0/14 */
    {0x11f80000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11f88000u, PROTO_APPLE, 17}, /* 17.248.128.0/17 */
    {0x11f89000u, PROTO_APPLE, 21}, /* 17.248.144.0/21 */
    {0x11f89800u, PROTO_APPLE, 17}, /* 17.248.128.0/17 */
    {0x11f90000u, PROTO_APPLE, 16}, /* 17.249.0.0/16 */
    {0x11f98000u, PROTO_APPLE, 17}, /* 17.249.128.0/17 */
    {0x11fa0000u, PROTO_APPLE, 16}, /* 17.250.0.0/16 */
    {0x11fa1000u, PROTO_APPLE, 20}, /* 17.250.16.0/20 */
    {0x11fa2000u, PROTO_APPLE, 16}, /* 17.250.0.0/16 */
    {0x11fa3000u, PROTO_APPLE, 24}, /* 17.250.48.0/24 */
    {0x11fa3100u, PROTO_APPLE, 16}, /* 17.250.0.0/16 */
    {0x11fa8000u, PROTO_APPLE, 17}, /* 17.250.128.0/17 */
    {0x11faf800u, PROTO_APPLE, 23}, /* 17.250.248.0/23 */
    {0x11fafa00u, PROTO_APPLE, 17}, /* 17.250.128.0/17 */
    {0x11fb0000u, PROTO_APPLE, 16}, /* 17.251.0.0/16 */
    {0x11fc1000u, PROTO_APPLE, 20}, /* 17.252.16.0/20 */
    {0x11fc2000u, PROTO_APPLE, 16}, /* 17.252.0.0/16 */
    {0x11fc4000u, PROTO_APPLE, 20}, /* 17.252.64.0/20 */
    {0x11fc4100u, PROTO_APPLE, 24}, /* 17.252.65.0/24 */
    {0x11fc4200u, PROTO_APPLE, 20}, /* 17.252.64.0/20 */
    {0x11fc6000u, PROTO_APPLE, 16}, /* 17.252.0.0/16 */
    {0x11fc8000u, PROTO_APPLE, 17}, /* 17.252.128.0/17 */
    {0x11fd0000u, PROTO_APPLE, 24}, /* 17.253.0.0/24 */
    {0x11fd0100u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd0800u, PROTO_APPLE, 24}, /* 17.253.8.0/24 */
    {0x11fd0900u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd1000u, PROTO_APPLE, 24}, /* 17.253.16.0/24 */
    {0x11fd1100u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd1200u, PROTO_APPLE, 24}, /* 17.253.18.0/24 */
    {0x11fd1300u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd1400u, PROTO_APPLE, 24}, /* 17.253.20.0/24 */
    {0x11fd1500u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd1600u, PROTO_APPLE, 24}, /* 17.253.22.0/24 */
    {0x11fd1700u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd2000u, PROTO_APPLE, 24}, /* 17.253.32.0/24 */
    {0x11fd2100u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd2200u, PROTO_APPLE, 24}, /* 17.253.34.0/24 */
    {0x11fd2300u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd3000u, PROTO_APPLE, 24}, /* 17.253.48.0/24 */
    {0x11fd3200u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd3600u, PROTO_APPLE, 23}, /* 17.253.54.0/23 */
    {0x11fd3a00u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd4000u, PROTO_APPLE, 24}, /* 17.253.64.0/24 */
    {0x11fd4100u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd4200u, PROTO_APPLE, 24}, /* 17.253.66.0/24 */
    {0x11fd4300u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd4400u, PROTO_APPLE, 24}, /* 17.253.68.0/24 */
    {0x11fd4500u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd4600u, PROTO_APPLE, 23}, /* 17.253.70.0/23 */
    {0x11fd4800u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd5000u, PROTO_APPLE, 24}, /* 17.253.80.0/24 */
    {0x11fd5100u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd5800u, PROTO_APPLE, 23}, /* 17.253.88.0/23 */
    {0x11fd5a00u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fd8000u, PROTO_APPLE, 21}, /* 17.253.128.0/21 */
    {0x11fd8800u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fdc400u, PROTO_APPLE, 24}, /* 17.253.196.0/24 */
    {0x11fdc500u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fdc700u, PROTO_APPLE, 24}, /* 17.253.199.0/24 */
    {0x11fdca00u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fdce00u, PROTO_APPLE, 24}, /* 17.253.206.0/24 */
    {0x11fdd000u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fdd800u, PROTO_APPLE, 23}, /* 17.253.216.0/23 */
    {0x11fdda00u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fe0000u, PROTO_APPLE, 24}, /* 17.254.0.0/24 */
    {0x11fe0400u, PROTO_APPLE, 22}, /* 17.254.4.0/22 */
    {0x11fe0600u, PROTO_APPLE, 24}, /* 17.254.6.0/24 */
    {0x11fe0700u, PROTO_APPLE, 22}, /* 17.254.4.0/22 */
    {0x11fe0c00u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fe0d00u, PROTO_APPLE, 24}, /* 17.254.13.0/24 */
    {0x11fe0e00u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fe1000u, PROTO_APPLE, 24}, /* 17.254.16.0/24 */
    {0x11fe1100u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fe1300u, PROTO_APPLE, 24}, /* 17.254.19.0/24 */
    {0x11fe1400u, PROTO_APPLE, 22}, /* 17.254.20.0/22 */
    {0x11fe1800u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fe2000u, PROTO_APPLE, 24}, /* 17.254.32.0/24 */
    {0x11fe2100u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fe3000u, PROTO_APPLE, 23}, /* 17.254.48.0/23 */
    {0x11fe3200u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fef800u, PROTO_APPLE, 23}, /* 17.254.248.0/23 */
    {0x11fefa00u, PROTO_APPLE, 9}, /* 17.128.0.0/9 */
    {0x11fefc00u, PROTO_APPLE, 24}, /* 17.254.252.0/24 */
    {0x11ff0000u, PROTO_APPLE, 16}, /* 17.255.0.0/16 */
    {0x11fff800u, PROTO_APPLE, 23}, /* 17.255.248.0/23 */
    {0x11fffc00u, PROTO_APPLE, 24}, /* 17.255.252.0/24 */
    {0x11fffd00u, PROTO_APPLE, 16}, /* 17.255.0.0/16 */
    {0x12000000u, PROTO_UNKNOWN, 0},
    {0x12220000u, PROTO_AWS, 19}, /* 18.34.0.0/19 */
    {0x12222000u, PROTO_UNKNOWN, 0},
    {0x12223000u, PROTO_AWS, 20}, /* 18.34.48.0/20 */
    {0x12224000u, PROTO_UNKNOWN, 0},
    {0x12224800u, PROTO_AWS, 21}, /* 18.34.72.0/21 */
    {0x12225000u, PROTO_UNKNOWN, 0},
    {0x1222e800u, PROTO_AWS, 21}, /* 18.34.232.0/21 */
    {0x1222f000u, PROTO_UNKNOWN, 0},
    {0x1222f400u, PROTO_AWS, 22}, /* 18.34.244.0/22 */
    {0x1222f800u, PROTO_UNKNOWN, 0},
    {0x1222fc00u, PROTO_AWS, 22}, /* 18.34.252.0/22 */
    {0x12230000u, PROTO_UNKNOWN, 0},
    {0x123c0000u, PROTO_AWS, 15}, /* 18.60.0.0/15 */
    {0x123e0000u, PROTO_UNKNOWN, 0},
    {0x12400000u, PROTO_CLOUDFRONT, 14}, /* 18.64.0.0/14 */
    {0x12440000u, PROTO_CLOUDFRONT, 16}, /* 18.68.0.0/16 */
    {0x12450000u, PROTO_UNKNOWN, 0},
    {0x12580000u, PROTO_AWS, 17}, /* 18.88.0.0/17 */
    {0x12588000u, PROTO_AWS, 18}, /* 18.88.128.0/18 */
    {0x1258c000u, PROTO_UNKNOWN, 0},
    {0x12590000u, PROTO_AWS, 18}, /* 18.89.0.0/18 */
    {0x12594000u, PROTO_UNKNOWN, 0},
    {0x12598000u, PROTO_AWS, 18}, /* 18.89.128.0/18 */
    {0x1259c000u, PROTO_UNKNOWN, 0},
    {0x12600000u, PROTO_AWS, 14}, /* 18.96.0.0/14 */
    {0x12640000u, PROTO_AWS, 15}, /* 18.100.0.0/15 */
    {0x12660000u, PROTO_AWS, 16}, /* 18.102.0.0/16 */
    {0x12670000u, PROTO_UNKNOWN, 0},
    {0x12740000u, PROTO_AWS, 14}, /* 18.116.0.0/14 */
    {0x12780000u, PROTO_UNKNOWN, 0},
    {0x12820000u, PROTO_AWS, 16}, /* 18.130.0.0/16 */
    {0x12830000u, PROTO_UNKNOWN, 0},
    {0x12840000u, PROTO_AWS, 14}, /* 18.132.0.0/14 */
    {0x12880000u, PROTO_AWS, 16}, /* 18.136.0.0/16 */
    {0x12890000u, PROTO_UNKNOWN, 0},
    {0x128a0000u, PROTO_AWS, 15}, /* 18.138.0.0/15 */
    {0x128c0000u, PROTO_AWS, 14}, /* 18.140.0.0/14 */
    {0x12900000u, PROTO_AWS, 15}, /* 18.144.0.0/15 */
    {0x12920000u, PROTO_UNKNOWN, 0},
    {0x12990000u, PROTO_AWS, 16}, /* 18.153.0.0/16 */
    {0x129a0000u, PROTO_CLOUDFRONT, 15}, /* 18.154.0.0/15 */
    {0x129c0000u, PROTO_AWS, 14}, /* 18.156.0.0/14 */
    {0x12a00000u, PROTO_CLOUDFRONT, 15}, /* 18.160.0.0/15 */
    {0x12a20000u, PROTO_AWS, 15}, /* 18.162.0.0/15 */
    {0x12a40000u, PROTO_CLOUDFRONT, 15}, /* 18.164.0.0/15 */
    {0x12a60000u, PROTO_AWS, 15}, /* 18.166.0.0/15 */
    {0x12a80000u, PROTO_AWS, 14}, /* 18.168.0.0/14 */
    {0x12ac0000u, PROTO_CLOUDFRONT, 15}, /* 18.172.0.0/15 */
    {0x12ae0000u, PROTO_UNKNOWN, 0},
    {0x12af0000u, PROTO_AWS, 18}, /* 18.175.0.0/18 */
    {0x12af4000u, PROTO_AWS, 24}, /* 18.175.64.0/24 */
    {0x12af4100u, PROTO_CLOUDFRONT, 24}, /* 18.175.65.0/24 */
    {0x12af4200u, PROTO_CLOUDFRONT, 23}, /* 18.175.66.0/23 */
    {0x12af4400u, PROTO_AWS, 22}, /* 18.175.68.0/22 */
    {0x12af4800u, PROTO_AWS, 21}, /* 18.175.72.0/21 */
    {0x12af5000u, PROTO_AWS, 20}, /* 18.175.80.0/20 */
    {0x12af6000u, PROTO_AWS, 19}, /* 18.175.96.0/19 */
    {0x12af8000u, PROTO_AWS, 17}, /* 18.175.128.0/17 */
    {0x12b00000u, PROTO_AWS, 13}, /* 18.176.0.0/13 */
    {0x12b80000u, PROTO_AWS, 15}, /* 18.184.0.0/15 */
    {0x12ba0000u, PROTO_UNKNOWN, 0},
    {0x12bc0000u, PROTO_AWS, 14}, /* 18.188.0.0/14 */
    {0x12c00000u, PROTO_AWS, 17}, /* 18.192.0.0/17 */
    {0x12c08000u, PROTO_AWS, 21}, /* 18.192.128.0/21 */
    {0x12c08800u, PROTO_AWS, 22}, /* 18.192.136.0/22 */
    {0x12c08c00u, PROTO_AWS, 23}, /* 18.192.140.0/23 */
    {0x12c08e00u, PROTO_CLOUDFRONT, 23}, /* 18.192.142.0/23 */
    {0x12c09000u, PROTO_AWS, 20}, /* 18.192.144.0/20 */
    {0x12c0a000u, PROTO_AWS, 19}, /* 18.192.160.0/19 */
    {0x12c0c000u, PROTO_AWS, 18}, /* 18.192.192.0/18 */
    {0x12c10000u, PROTO_AWS, 16}, /* 18.193.0.0/16 */
    {0x12c20000u, PROTO_AWS, 15}, /* 18.194.0.0/15 */
    {0x12c60000u, PROTO_AWS, 16}, /* 18.198.0.0/16 */
    {0x12c70000u, PROTO_AWS, 18}, /* 18.199.0.0/18 */
    {0x12c74000u, PROTO_AWS, 22}, /* 18.199.64.0/22 */
    {0x12c74400u, PROTO_CLOUDFRONT, 22}, /* 18.199.68.0/22 */
    {0x12c74800u, PROTO_CLOUDFRONT, 21}, /* 18.199.72.0/21 */
    {0x12c75000u, PROTO_AWS, 20}, /* 18.199.80.0/20 */
    {0x12c76000u, PROTO_AWS, 19}, /* 18.199.96.0/19 */
    {0x12c78000u, PROTO_AWS, 17}, /* 18.199.128.0/17 */
    {0x12c88000u, PROTO_AWS, 18}, /* 18.200.128.0/18 */
    {0x12c8c000u, PROTO_AWS, 20}, /* 18.200.192.0/20 */
    {0x12c8d000u, PROTO_AWS, 22}, /* 18.200.208.0/22 */
    {0x12c8d400u, PROTO_CLOUDFRONT, 23}, /* 18.200.212.0/23 */
    {0x12c8d600u, PROTO_AWS, 23}, /* 18.200.214.0/23 */
    {0x12c8d800u, PROTO_AWS, 21}, /* 18.200.216.0/21 */
    {0x12c8e000u, PROTO_AWS, 19}, /* 18.200.224.0/19 */
    {0x12c90000u, PROTO_AWS, 16}, /* 18.201.0.0/16 */
    {0x12ca0000u, PROTO_AWS, 15}, /* 18.202.0.0/15 */
    {0x12cc0000u, PROTO_AWS, 14}, /* 18.204.0.0/14 */
    {0x12d00000u, PROTO_AWS, 13}, /* 18.208.0.0/13 */
    {0x12d80000u, PROTO_AWS, 17}, /* 18.216.0.0/17 */
    {0x12d88000u, PROTO_AWS, 19}, /* 18.216.128.0/19 */
    {0x12d8a000u, PROTO_AWS, 21}, /* 18.216.160.0/21 */
    {0x12d8a800u, PROTO_AWS, 23}, /* 18.216.168.0/23 */
    {0x12d8aa00u, PROTO_AWS, 25}, /* 18.216.170.0/25 */
    {0x12d8aa80u, PROTO_CLOUDFRONT, 25}, /* 18.216.170.128/25 */
    {0x12d8ab00u, PROTO_AWS, 24}, /* 18.216.171.0/24 */
    {0x12d8ac00u, PROTO_AWS, 22}, /* 18.216.172.0/22 */
    {0x12d8b000u, PROTO_AWS, 20}, /* 18.216.176.0/20 */
    {0x12d8c000u, PROTO_AWS, 18}, /* 18.216.192.0/18 */
    {0x12d90000u, PROTO_AWS, 16}, /* 18.217.0.0/16 */
    {0x12da0000u, PROTO_AWS, 15}, /* 18.218.0.0/15 */
    {0x12dc0000u, PROTO_AWS, 14}, /* 18.220.0.0/14 */
    {0x12e40000u, PROTO_AWS, 16}, /* 18.228.0.0/16 */
    {0x12e50000u, PROTO_AWS, 17}, /* 18.229.0.0/17 */
    {0x12e58000u, PROTO_AWS, 18}, /* 18.229.128.0/18 */
    {0x12e5c000u, PROTO_AWS, 20}, /* 18.229.192.0/20 */
    {0x12e5d000u, PROTO_AWS, 21}, /* 18.229.208.0/21 */
    {0x12e5d800u, PROTO_AWS, 22}, /* 18.229.216.0/22 */
    {0x12e5dc00u, PROTO_AWS, 25}, /* 18.229.220.0/25 */
    {0x12e5dc80u, PROTO_AWS, 26}, /* 18.229.220.128/26 */
    {0x12e5dcc0u, PROTO_CLOUDFRONT, 26}, /* 18.229.220.192/26 */
    {0x12e5dd00u, PROTO_AWS, 24}, /* 18.229.221.0/24 */
    {0x12e5de00u, PROTO_AWS, 23}, /* 18.229.222.0/23 */
    {0x12e5e000u, PROTO_AWS, 19}, /* 18.229.224.0/19 */
    {0x12e60000u, PROTO_AWS, 17}, /* 18.230.0.0/17 */
    {0x12e68000u, PROTO_AWS, 18}, /* 18.230.128.0/18 */
    {0x12e6c000u, PROTO_AWS, 19}, /* 18.230.192.0/19 */
    {0x12e6e000u, PROTO_AWS, 22}, /* 18.230.224.0/22 */
    {0x12e6e400u, PROTO_AWS, 24}, /* 18.230.228.0/24 */
    {0x12e6e500u, PROTO_CLOUDFRONT, 24}, /* 18.230.229.0/24 */
    {0x12e6e600u, PROTO_CLOUDFRONT, 25}, /* 18.230.230.0/25 */
    {0x12e6e680u, PROTO_AWS, 25}, /* 18.230.230.128/25 */
    {0x12e6e700u, PROTO_AWS, 24}, /* 18.230.231.0/24 */
    {0x12e6e800u, PROTO_AWS, 21}, /* 18.230.232.0/21 */
    {0x12e6f000u, PROTO_AWS, 20}, /* 18.230.240.0/20 */
    {0x12e70000u, PROTO_AWS, 16}, /* 18.231.0.0/16 */
    {0x12e80000u, PROTO_AWS, 14}, /* 18.232.0.0/14 */
    {0x12ec0000u, PROTO_AWS, 15}, /* 18.236.0.0/15 */
    {0x12ee0000u, PROTO_CLOUDFRONT, 15}, /* 18.238.0.0/15 */
    {0x12f00000u, PROTO_UNKNOWN, 0},
    {0x12f40000u, PROTO_CLOUDFRONT, 15}, /* 18.244.0.0/15 */
    {0x12f60000u, PROTO_AWS, 16}, /* 18.246.0.0/16 */
    {0x12f70000u, PROTO_UNKNOWN, 0},
    {0x12fc0000u, PROTO_AWS, 15}, /* 18.252.0.0/15 */
    {0x12fe0000u, PROTO_AWS, 16}, /* 18.254.0.0/16 */
    {0x12ff0000u, PROTO_UNKNOWN, 0},
    {0x14000000u, PROTO_AZURE, 12}, /* 20.0.0.0/12 */
    {0x14100000u, PROTO_AZURE, 14}, /* 20.16.0.0/14 */
    {0x14140000u, PROTO_UNKNOWN, 0},
    {0x14142000u, PROTO_AZURE, 19}, /* 20.20.32.0/19 */
    {0x14144000u, PROTO_AZURE, 18}, /* 20.20.64.0/18 */
    {0x14148000u, PROTO_AZURE, 17}, /* 20.20.128.0/17 */
    {0x14150000u, PROTO_AZURE, 16}, /* 20.21.0.0/16 */
    {0x14160000u, PROTO_AZURE, 15}, /* 20.22.0.0/15 */
    {0x14180000u, PROTO_AZURE, 14}, /* 20.24.0.0/14 */
    {0x141c0000u, PROTO_AZURE, 15}, /* 20.28.0.0/15 */
    {0x141e0000u, PROTO_UNKNOWN, 0},
    {0x141f0000u, PROTO_AZURE, 16}, /* 20.31.0.0/16 */
    {0x14200000u, PROTO_UNKNOWN, 0},
    {0x14210000u, PROTO_AZURE, 16}, /* 20.33.0.0/16 */
    {0x14220000u, PROTO_UNKNOWN, 0},
    {0x14240000u, PROTO_AZURE, 14}, /* 20.36.0.0/14 */
    {0x14280000u, PROTO_AZURE, 13}, /* 20.40.0.0/13 */
    {0x14300000u, PROTO_AZURE, 12}, /* 20.48.0.0/12 */
    {0x14400000u, PROTO_AZURE, 10}, /* 20.64.0.0/10 */
    {0x14800000u, PROTO_UNKNOWN, 0},
    {0x14870000u, PROTO_AZURE, 16}, /* 20.135.0.0/16 */
    {0x14880000u, PROTO_AZURE, 22}, /* 20.136.0.0/22 */
    {0x14880400u, PROTO_AZURE, 23}, /* 20.136.4.0/23 */
    {0x14880600u, PROTO_UNKNOWN, 0},
    {0x14880700u, PROTO_AZURE, 25}, /* 20.136.7.0/25 */
    {0x14880780u, PROTO_UNKNOWN, 0},
    {0x14888000u, PROTO_AZURE, 24}, /* 20.136.128.0/24 */
    {0x14888100u, PROTO_AZURE, 25}, /* 20.136.129.0/25 */
    {0x14888180u, PROTO_UNKNOWN, 0},
    {0x148f0000u, PROTO_AZURE, 16}, /* 20.143.0.0/16 */
    {0x14900000u, PROTO_UNKNOWN, 0},
    {0x14960000u, PROTO_AZURE, 15}, /* 20.150.0.0/15 */
    {0x149a0000u, PROTO_UNKNOWN, 0},
    {0x149d0000u, PROTO_AZURE, 16}, /* 20.157.0.0/16 */
    {0x149e0000u, PROTO_UNKNOWN, 0},
    {0x14a00000u, PROTO_AZURE, 12}, /* 20.160.0.0/12 */
    {0x14b00000u, PROTO_UNKNOWN, 0},
    {0x14b80000u, PROTO_AZURE, 13}, /* 20.184.0.0/13 */
    {0x14c00000u, PROTO_AZURE, 10}, /* 20.192.0.0/10 */
    {0x15000000u, PROTO_UNKNOWN, 0},
    {0x17140000u, PROTO_AWS, 14}, /* 23.20.0.0/14 */
    {0x17180000u, PROTO_UNKNOWN, 0},
    {0x175b0000u, PROTO_CLOUDFRONT, 19}, /* 23.91.0.0/19 */
    {0x175b2000u, PROTO_UNKNOWN, 0},
    {0x17600000u, PROTO_AZURE, 16}, /* 23.96.0.0/16 */
    {0x17610000u, PROTO_UNKNOWN, 0},
    {0x17613000u, PROTO_AZURE, 20}, /* 23.97.48.0/20 */
    {0x17614000u, PROTO_AZURE, 18}, /* 23.97.64.0/18 */
    {0x17618000u, PROTO_AZURE, 17}, /* 23.97.128.0/17 */
    {0x17620000u, PROTO_UNKNOWN, 0},
    {0x17622000u, PROTO_AZURE, 19}, /* 23.98.32.0/19 */
    {0x17624000u, PROTO_AZURE, 18}, /* 23.98.64.0/18 */
    {0x17628000u, PROTO_AZURE, 17}, /* 23.98.128.0/17 */
    {0x17630000u, PROTO_AZURE, 16}, /* 23.99.0.0/16 */
    {0x17650000u, PROTO_AZURE, 19}, /* 23.101.0.0/19 */
    {0x17652000u, PROTO_AZURE, 21}, /* 23.101.32.0/21 */
    {0x17652800u, PROTO_UNKNOWN, 0},
    {0x17653000u, PROTO_AZURE, 20}, /* 23.101.48.0/20 */
    {0x17655000u, PROTO_AZURE, 21}, /* 23.101.80.0/21 */
    {0x17655800u, PROTO_UNKNOWN, 0},
    {0x17657000u, PROTO_AZURE, 20}, /* 23.101.112.0/20 */
    {0x17658000u, PROTO_AZURE, 17}, /* 23.101.128.0/17 */
    {0x17660000u, PROTO_AZURE, 16}, /* 23.102.0.0/16 */
    {0x17670000u, PROTO_UNKNOWN, 0},
    {0x17674000u, PROTO_AZURE, 18}, /* 23.103.64.0/18 */
    {0x17678000u, PROTO_UNKNOWN, 0},
    {0x17a00000u, PROTO_AWS, 24}, /* 23.160.0.0/24 */
    {0x17a00100u, PROTO_UNKNOWN, 0},
    {0x17e4c400u, PROTO_AWS, 23}, /* 23.228.196.0/23 */
    {0x17e4c600u, PROTO_AWS, 24}, /* 23.228.198.0/24 */
    {0x17e4c700u, PROTO_UNKNOWN, 0},
    {0x17e4d400u, PROTO_CLOUDFRONT, 23}, /* 23.228.212.0/23 */
    {0x17e4d600u, PROTO_CLOUDFRONT, 24}, /* 23.228.214.0/24 */
    {0x17e4d700u, PROTO_UNKNOWN, 0},
    {0x17e4db00u, PROTO_AWS, 24}, /* 23.228.219.0/24 */
    {0x17e4dc00u, PROTO_CLOUDFRONT, 22}, /* 23.228.220.0/22 */
    {0x17e4e000u, PROTO_UNKNOWN, 0},
    {0x17e4e400u, PROTO_AWS, 22}, /* 23.228.228.0/22 */
    {0x17e4e800u, PROTO_UNKNOWN, 0},
    {0x17e4f400u, PROTO_CLOUDFRONT, 24}, /* 23.228.244.0/24 */
    {0x17e4f500u, PROTO_UNKNOWN, 0},
    {0x17e4f600u, PROTO_CLOUDFRONT, 23}, /* 23.228.246.0/23 */
    {0x17e4f800u, PROTO_CLOUDFRONT, 22}, /* 23.228.248.0/22 */
    {0x17e4fc00u, PROTO_UNKNOWN, 0},
    {0x17eac000u, PROTO_CLOUDFRONT, 18}, /* 23.234.192.0/18 */
    {0x17eb0000u, PROTO_UNKNOWN, 0},
    {0x17eb2000u, PROTO_FASTLY, 20}, /* 23.235.32.0/20 */
    {0x17eb3000u, PROTO_UNKNOWN, 0},
    {0x17ec3000u, PROTO_GOOGLE_CLOUD, 20}, /* 23.236.48.0/20 */
    {0x17ec4000u, PROTO_UNKNOWN, 0},
    {0x17ee8000u, PROTO_AWS, 17}, /* 23.238.128.0/17 */
    {0x17ef0000u, PROTO_UNKNOWN, 0},
    {0x17f60000u, PROTO_NETFLIX, 18}, /* 23.246.0.0/18 */
    {0x17f60f00u, PROTO_NETFLIX, 24}, /* 23.246.15.0/24 */
    {0x17f61000u, PROTO_NETFLIX, 18}, /* 23.246.0.0/18 */
    {0x17f61400u, PROTO_NETFLIX, 24}, /* 23.246.20.0/24 */
    {0x17f61500u, PROTO_NETFLIX, 18}, /* 23.246.0.0/18 */
    {0x17f61c00u, PROTO_NETFLIX, 24}, /* 23.246.28.0/24 */
    {0x17f62000u, PROTO_NETFLIX, 18}, /* 23.246.0.0/18 */
    {0x17f64000u, PROTO_UNKNOWN, 0},
    {0x17fb8000u, PROTO_GOOGLE_CLOUD, 19}, /* 23.251.128.0/19 */
    {0x17fba000u, PROTO_UNKNOWN, 0},
    {0x17fe0000u, PROTO_AWS, 19}, /* 23.254.0.0/19 */
    {0x17fe2000u, PROTO_AWS, 21}, /* 23.254.32.0/21 */
    {0x17fe2800u, PROTO_AWS, 23}, /* 23.254.40.0/23 */
    {0x17fe2a00u, PROTO_UNKNOWN, 0},
    {0x17fe7800u, PROTO_AWS, 21}, /* 23.254.120.0/21 */
    {0x17fe8000u, PROTO_UNKNOWN, 0},
    {0x186e0000u, PROTO_AWS, 21}, /* 24.110.0.0/21 */
    {0x186e0800u, PROTO_AWS, 23}, /* 24.110.8.0/23 */
    {0x186e0a00u, PROTO_UNKNOWN, 0},
    {0x186e1000u, PROTO_AWS, 20}, /* 24.110.16.0/20 */
    {0x186e2000u, PROTO_CLOUDFRONT, 19}, /* 24.110.32.0/19 */
    {0x186e4000u, PROTO_UNKNOWN, 0},
    {0x186e8000u, PROTO_CLOUDFRONT, 17}, /* 24.110.128.0/17 */
    {0x186f0000u, PROTO_UNKNOWN, 0},
    {0x1b000000u, PROTO_AWS, 22}, /* 27.0.0.0/22 */
    {0x1b000400u, PROTO_UNKNOWN, 0},
    {0x1b00ec00u, PROTO_KAKAO, 22}, /* 27.0.236.0/22 */
    {0x1b00ed00u, PROTO_KAKAO, 24}, /* 27.0.237.0/24 */
    {0x1b00f000u, PROTO_UNKNOWN, 0},
    {0x1b7b2400u, PROTO_YAHOO, 24}, /* 27.123.36.0/24 */
    {0x1b7b2500u, PROTO_UNKNOWN, 0},
    {0x1b7b2700u, PROTO_YAHOO, 24}, /* 27.123.39.0/24 */
    {0x1b7b2800u, PROTO_UNKNOWN, 0},
    {0x1b85e000u, PROTO_YAHOO, 22}, /* 27.133.224.0/22 */
    {0x1b85e400u, PROTO_UNKNOWN, 0},
    {0x1b85f000u, PROTO_YAHOO, 24}, /* 27.133.240.0/24 */
    {0x1b85f400u, PROTO_UNKNOWN, 0},
    {0x1f0d1800u, PROTO_FACEBOOK, 21}, /* 31.13.24.0/21 */
    {0x1f0d2000u, PROTO_UNKNOWN, 0},
    {0x1f0d4000u, PROTO_FACEBOOK, 18}, /* 31.13.64.0/18 */
    {0x1f0d4100u, PROTO_FACEBOOK, 24}, /* 31.13.65.0/24 */
    {0x1f0d6000u, PROTO_FACEBOOK, 19}, /* 31.13.96.0/19 */
    {0x1f0d8000u, PROTO_UNKNOWN, 0},
    {0x1fdcdc00u, PROTO_AWS, 22}, /* 31.220.220.0/22 */
    {0x1fdce000u, PROTO_UNKNOWN, 0},
    {0x1fdceb00u, PROTO_AWS, 24}, /* 31.220.235.0/24 */
    {0x1fdced00u, PROTO_UNKNOWN, 0},
    {0x1fdcf700u, PROTO_AWS, 24}, /* 31.220.247.0/24 */
    {0x1fdcf800u, PROTO_UNKNOWN, 0},
    {0x1fdcfc00u, PROTO_AWS, 24}, /* 31.220.252.0/24 */
    {0x1fdcfd00u, PROTO_UNKNOWN, 0},
    {0x20b80000u, PROTO_AWS, 13}, /* 32.184.0.0/13 */
    {0x20c00000u, PROTO_AWS, 12}, /* 32.192.0.0/12 */
    {0x20d00000u, PROTO_UNKNOWN, 0},
    {0x20e80000u, PROTO_AWS, 16}, /* 32.232.0.0/16 */
    {0x20e90000u, PROTO_UNKNOWN, 0},
    {0x20ec0000u, PROTO_AWS, 15}, /* 32.236.0.0/15 */
    {0x20ee0000u, PROTO_UNKNOWN, 0},
    {0x20f00000u, PROTO_AWS, 15}, /* 32.240.0.0/15 */
    {0x20f20000u, PROTO_UNKNOWN, 0},
    {0x22000000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.0.0.0/17 */
    {0x22008000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.0.128.0/18 */
    {0x2200c000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.0.192.0/19 */
    {0x2200e000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.0.224.0/22 */
    {0x2200e400u, PROTO_GOOGLE, 22}, /* 34.0.228.0/22 */
    {0x2200e800u, PROTO_GOOGLE, 21}, /* 34.0.232.0/21 */
    {0x2200f000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.0.240.0/20 */
    {0x22010000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.1.0.0/18 */
    {0x22014000u, PROTO_GOOGLE, 18}, /* 34.1.64.0/18 */
    {0x22018000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.1.128.0/17 */
    {0x22020000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.2.0.0/18 */
    {0x22024000u, PROTO_GOOGLE, 21}, /* 34.2.64.0/21 */
    {0x22024800u, PROTO_GOOGLE, 22}, /* 34.2.72.0/22 */
    {0x22024c00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.2.76.0/23 */
    {0x22024e00u, PROTO_GOOGLE, 23}, /* 34.2.78.0/23 */
    {0x22025000u, PROTO_GOOGLE, 20}, /* 34.2.80.0/20 */
    {0x22026000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.2.96.0/20 */
    {0x22027000u, PROTO_GOOGLE, 20}, /* 34.2.112.0/20 */
    {0x22028000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.2.128.0/17 */
    {0x22030000u, PROTO_GOOGLE, 23}, /* 34.3.0.0/23 */
    {0x22030200u, PROTO_UNKNOWN, 0},
    {0x22030300u, PROTO_GOOGLE, 24}, /* 34.3.3.0/24 */
    {0x22030500u, PROTO_UNKNOWN, 0},
    {0x22030800u, PROTO_GOOGLE, 21}, /* 34.3.8.0/21 */
    {0x22031000u, PROTO_GOOGLE, 20}, /* 34.3.16.0/20 */
    {0x22032000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.3.32.0/20 */
    {0x22033000u, PROTO_GOOGLE, 20}, /* 34.3.48.0/20 */
    {0x22034000u, PROTO_GOOGLE, 21}, /* 34.3.64.0/21 */
    {0x22034800u, PROTO_GOOGLE, 22}, /* 34.3.72.0/22 */
    {0x22034c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.3.76.0/22 */
    {0x22035000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.3.80.0/20 */
    {0x22037000u, PROTO_GOOGLE, 20}, /* 34.3.112.0/20 */
    {0x22038000u, PROTO_UNKNOWN, 0},
    {0x22040000u, PROTO_GOOGLE, 20}, /* 34.4.0.0/20 */
    {0x22041000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.4.16.0/22 */
    {0x22041400u, PROTO_GOOGLE, 22}, /* 34.4.20.0/22 */
    {0x22041800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.4.24.0/21 */
    {0x22042000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.4.32.0/19 */
    {0x22046000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.4.96.0/22 */
    {0x22046400u, PROTO_GOOGLE_CLOUD, 24}, /* 34.4.100.0/24 */
    {0x22046500u, PROTO_GOOGLE, 24}, /* 34.4.101.0/24 */
    {0x22046600u, PROTO_GOOGLE_CLOUD, 23}, /* 34.4.102.0/23 */
    {0x22046800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.4.104.0/21 */
    {0x22047000u, PROTO_GOOGLE, 20}, /* 34.4.112.0/20 */
    {0x22048000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.4.128.0/18 */
    {0x2204c000u, PROTO_GOOGLE_CLOUD, 24}, /* 34.4.192.0/24 */
    {0x2204c100u, PROTO_GOOGLE, 24}, /* 34.4.193.0/24 */
    {0x2204c200u, PROTO_GOOGLE, 23}, /* 34.4.194.0/23 */
    {0x2204c400u, PROTO_GOOGLE, 22}, /* 34.4.196.0/22 */
    {0x2204c800u, PROTO_GOOGLE, 21}, /* 34.4.200.0/21 */
    {0x2204d000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.4.208.0/20 */
    {0x2204e000u, PROTO_GOOGLE, 19}, /* 34.4.224.0/19 */
    {0x22050000u, PROTO_GOOGLE, 16}, /* 34.5.0.0/16 */
    {0x22060000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.6.0.0/15 */
    {0x22080000u, PROTO_GOOGLE_CLOUD, 14}, /* 34.8.0.0/14 */
    {0x220c0000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.12.0.0/16 */
    {0x220d0000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.13.0.0/18 */
    {0x220d4000u, PROTO_GOOGLE, 22}, /* 34.13.64.0/22 */
    {0x220d4400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.13.68.0/22 */
    {0x220d4800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.13.72.0/21 */
    {0x220d5000u, PROTO_GOOGLE, 20}, /* 34.13.80.0/20 */
    {0x220d7000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.13.112.0/20 */
    {0x220d8000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.13.128.0/17 */
    {0x220e0000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.14.0.0/15 */
    {0x22100000u, PROTO_GOOGLE_CLOUD, 12}, /* 34.16.0.0/12 */
    {0x22200000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.32.0.0/15 */
    {0x22220000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.34.0.0/17 */
    {0x22228000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.34.128.0/18 */
    {0x2222c000u, PROTO_GOOGLE, 20}, /* 34.34.192.0/20 */
    {0x2222d000u, PROTO_GOOGLE, 21}, /* 34.34.208.0/21 */
    {0x2222d800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.34.216.0/21 */
    {0x2222e000u, PROTO_GOOGLE, 19}, /* 34.34.224.0/19 */
    {0x22230000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.35.0.0/16 */
    {0x22240000u, PROTO_GOOGLE_CLOUD, 14}, /* 34.36.0.0/14 */
    {0x22280000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.40.0.0/15 */
    {0x222a0000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.42.0.0/16 */
    {0x222b0000u, PROTO_GOOGLE, 16}, /* 34.43.0.0/16 */
    {0x222c0000u, PROTO_GOOGLE_CLOUD, 14}, /* 34.44.0.0/14 */
    {0x22300000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.48.0.0/15 */
    {0x22320000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.50.0.0/17 */
    {0x22328000u, PROTO_GOOGLE, 20}, /* 34.50.128.0/20 */
    {0x22329000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.50.144.0/20 */
    {0x2232a000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.50.160.0/19 */
    {0x2232c000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.50.192.0/18 */
    {0x22330000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.51.0.0/16 */
    {0x22340000u, PROTO_GOOGLE, 17}, /* 34.52.0.0/17 */
    {0x22348000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.52.128.0/17 */
    {0x22350000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.53.0.0/16 */
    {0x22360000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.54.0.0/15 */
    {0x22380000u, PROTO_GOOGLE_CLOUD, 13}, /* 34.56.0.0/13 */
    {0x22400000u, PROTO_GOOGLE, 19}, /* 34.64.0.0/19 */
    {0x22402000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.64.32.0/19 */
    {0x22404000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.64.64.0/18 */
    {0x22408000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.64.128.0/17 */
    {0x22410000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.65.0.0/16 */
    {0x22420000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.66.0.0/15 */
    {0x22440000u, PROTO_GOOGLE_CLOUD, 14}, /* 34.68.0.0/14 */
    {0x22480000u, PROTO_GOOGLE_CLOUD, 13}, /* 34.72.0.0/13 */
    {0x22500000u, PROTO_GOOGLE_CLOUD, 12}, /* 34.80.0.0/12 */
    {0x22600000u, PROTO_GOOGLE, 18}, /* 34.96.0.0/18 */
    {0x22604000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.96.64.0/18 */
    {0x22608000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.96.128.0/17 */
    {0x22610000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.97.0.0/16 */
    {0x22620000u, PROTO_GOOGLE, 18}, /* 34.98.0.0/18 */
    {0x22624000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.98.64.0/18 */
    {0x22628000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.98.128.0/21 */
    {0x22628800u, PROTO_GOOGLE, 21}, /* 34.98.136.0/21 */
    {0x22629000u, PROTO_GOOGLE, 20}, /* 34.98.144.0/20 */
    {0x2262a000u, PROTO_GOOGLE, 19}, /* 34.98.160.0/19 */
    {0x2262c000u, PROTO_GOOGLE, 18}, /* 34.98.192.0/18 */
    {0x22630000u, PROTO_GOOGLE, 16}, /* 34.99.0.0/16 */
    {0x22640000u, PROTO_GOOGLE, 17}, /* 34.100.0.0/17 */
    {0x22648000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.100.128.0/17 */
    {0x22650000u, PROTO_GOOGLE, 20}, /* 34.101.0.0/20 */
    {0x22651000u, PROTO_GOOGLE, 23}, /* 34.101.16.0/23 */
    {0x22651200u, PROTO_GOOGLE_CLOUD, 24}, /* 34.101.18.0/24 */
    {0x22651300u, PROTO_GOOGLE, 24}, /* 34.101.19.0/24 */
    {0x22651400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.101.20.0/22 */
    {0x22651c00u, PROTO_GOOGLE, 22}, /* 34.101.28.0/22 */
    {0x22652000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.101.32.0/19 */
    {0x22654000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.101.64.0/18 */
    {0x22658000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.101.128.0/17 */
    {0x22660000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.102.0.0/16 */
    {0x22670000u, PROTO_GOOGLE, 16}, /* 34.103.0.0/16 */
    {0x22680000u, PROTO_GOOGLE, 20}, /* 34.104.0.0/20 */
    {0x22681000u, PROTO_GOOGLE, 21}, /* 34.104.16.0/21 */
    {0x22681800u, PROTO_GOOGLE, 23}, /* 34.104.24.0/23 */
    {0x22681a00u, PROTO_GOOGLE, 24}, /* 34.104.26.0/24 */
    {0x22681b00u, PROTO_GOOGLE_CLOUD, 24}, /* 34.104.27.0/24 */
    {0x22681c00u, PROTO_GOOGLE, 22}, /* 34.104.28.0/22 */
    {0x22682000u, PROTO_GOOGLE, 20}, /* 34.104.32.0/20 */
    {0x22683000u, PROTO_GOOGLE, 24}, /* 34.104.48.0/24 */
    {0x22683100u, PROTO_GOOGLE_CLOUD, 24}, /* 34.104.49.0/24 */
    {0x22683200u, PROTO_GOOGLE_CLOUD, 23}, /* 34.104.50.0/23 */
    {0x22683400u, PROTO_GOOGLE_CLOUD, 24}, /* 34.104.52.0/24 */
    {0x22683500u, PROTO_GOOGLE, 24}, /* 34.104.53.0/24 */
    {0x22683600u, PROTO_GOOGLE, 23}, /* 34.104.54.0/23 */
    {0x22683800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.104.56.0/21 */
    {0x22684000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.104.64.0/18 */
    {0x22688000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.104.128.0/17 */
    {0x22690000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.105.0.0/16 */
    {0x226a0000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.106.0.0/15 */
    {0x226c0000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.108.0.0/16 */
    {0x226d0000u, PROTO_GOOGLE, 16}, /* 34.109.0.0/16 */
    {0x226e0000u, PROTO_GOOGLE, 17}, /* 34.110.0.0/17 */
    {0x226e8000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.110.128.0/17 */
    {0x226f0000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.111.0.0/16 */
    {0x22700000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.112.0.0/15 */
    {0x22720000u, PROTO_GOOGLE, 15}, /* 34.114.0.0/15 */
    {0x22740000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.116.0.0/21 */
    {0x22740800u, PROTO_GOOGLE, 21}, /* 34.116.8.0/21 */
    {0x22741000u, PROTO_GOOGLE, 20}, /* 34.116.16.0/20 */
    {0x22742000u, PROTO_GOOGLE, 19}, /* 34.116.32.0/19 */
    {0x22744000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.116.64.0/18 */
    {0x22748000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.116.128.0/17 */
    {0x22750000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.117.0.0/16 */
    {0x22760000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.118.0.0/17 */
    {0x22768000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.118.128.0/18 */
    {0x2276c000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.118.192.0/20 */
    {0x2276d000u, PROTO_GOOGLE, 20}, /* 34.118.208.0/20 */
    {0x2276f000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.118.240.0/20 */
    {0x22770000u, PROTO_GOOGLE, 16}, /* 34.119.0.0/16 */
    {0x22780000u, PROTO_GOOGLE_CLOUD, 14}, /* 34.120.0.0/14 */
    {0x227c0000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.124.0.0/18 */
    {0x227c4000u, PROTO_GOOGLE, 19}, /* 34.124.64.0/19 */
    {0x227c6000u, PROTO_GOOGLE, 20}, /* 34.124.96.0/20 */
    {0x227c7000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.124.112.0/20 */
    {0x227c8000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.124.128.0/17 */
    {0x227d0000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.125.0.0/16 */
    {0x227e0000u, PROTO_GOOGLE, 18}, /* 34.126.0.0/18 */
    {0x227e4000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.126.64.0/18 */
    {0x227ec000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.126.192.0/19 */
    {0x227ee000u, PROTO_GOOGLE, 19}, /* 34.126.224.0/19 */
    {0x227f0000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.127.0.0/17 */
    {0x227f8000u, PROTO_GOOGLE, 20}, /* 34.127.128.0/20 */
    {0x227f9000u, PROTO_GOOGLE, 21}, /* 34.127.144.0/21 */
    {0x227f9800u, PROTO_GOOGLE, 22}, /* 34.127.152.0/22 */
    {0x227f9c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.127.156.0/22 */
    {0x227fa000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.127.160.0/20 */
    {0x227fb000u, PROTO_GOOGLE, 24}, /* 34.127.176.0/24 */
    {0x227fb100u, PROTO_GOOGLE_CLOUD, 24}, /* 34.127.177.0/24 */
    {0x227fb200u, PROTO_GOOGLE_CLOUD, 23}, /* 34.127.178.0/23 */
    {0x227fb400u, PROTO_GOOGLE_CLOUD, 24}, /* 34.127.180.0/24 */
    {0x227fb500u, PROTO_GOOGLE, 24}, /* 34.127.181.0/24 */
    {0x227fb600u, PROTO_GOOGLE, 23}, /* 34.127.182.0/23 */
    {0x227fb800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.127.184.0/21 */
    {0x227fc000u, PROTO_GOOGLE, 18}, /* 34.127.192.0/18 */
    {0x22800000u, PROTO_GOOGLE, 22}, /* 34.128.0.0/22 */
    {0x22800400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.128.4.0/22 */
    {0x22800800u, PROTO_GOOGLE, 21}, /* 34.128.8.0/21 */
    {0x22801000u, PROTO_GOOGLE, 20}, /* 34.128.16.0/20 */
    {0x22802000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.128.32.0/22 */
    {0x22802400u, PROTO_GOOGLE_CLOUD, 23}, /* 34.128.36.0/23 */
    {0x22802600u, PROTO_GOOGLE, 23}, /* 34.128.38.0/23 */
    {0x22802a00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.128.42.0/23 */
    {0x22802c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.128.44.0/22 */
    {0x22803000u, PROTO_GOOGLE_CLOUD, 23}, /* 34.128.48.0/23 */
    {0x22803200u, PROTO_GOOGLE, 23}, /* 34.128.50.0/23 */
    {0x22803400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.128.52.0/22 */
    {0x22803800u, PROTO_GOOGLE, 23}, /* 34.128.56.0/23 */
    {0x22803a00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.128.58.0/23 */
    {0x22803c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.128.60.0/22 */
    {0x22804000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.128.64.0/18 */
    {0x2280c000u, PROTO_GOOGLE, 20}, /* 34.128.192.0/20 */
    {0x2280d000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.128.208.0/20 */
    {0x2280f000u, PROTO_GOOGLE, 20}, /* 34.128.240.0/20 */
    {0x22810000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.129.0.0/16 */
    {0x22820000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.130.0.0/15 */
    {0x22840000u, PROTO_GOOGLE_CLOUD, 14}, /* 34.132.0.0/14 */
    {0x228c0000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.140.0.0/15 */
    {0x228e0000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.142.0.0/16 */
    {0x228f0000u, PROTO_GOOGLE, 18}, /* 34.143.0.0/18 */
    {0x228f4000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.143.64.0/21 */
    {0x228f4800u, PROTO_GOOGLE, 21}, /* 34.143.72.0/21 */
    {0x228f5000u, PROTO_GOOGLE, 20}, /* 34.143.80.0/20 */
    {0x228f6000u, PROTO_GOOGLE, 19}, /* 34.143.96.0/19 */
    {0x228f8000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.143.128.0/17 */
    {0x22900000u, PROTO_GOOGLE, 17}, /* 34.144.0.0/17 */
    {0x22908000u, PROTO_GOOGLE, 19}, /* 34.144.128.0/19 */
    {0x2290a000u, PROTO_GOOGLE, 21}, /* 34.144.160.0/21 */
    {0x2290a800u, PROTO_GOOGLE, 22}, /* 34.144.168.0/22 */
    {0x2290ac00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.144.172.0/22 */
    {0x2290b000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.144.176.0/20 */
    {0x2290c000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.144.192.0/18 */
    {0x22910000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.145.0.0/16 */
    {0x22920000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.146.0.0/15 */
    {0x22940000u, PROTO_GOOGLE_CLOUD, 14}, /* 34.148.0.0/14 */
    {0x22980000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.152.0.0/18 */
    {0x22984000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.152.64.0/22 */
    {0x22984400u, PROTO_GOOGLE_CLOUD, 23}, /* 34.152.68.0/23 */
    {0x22984600u, PROTO_GOOGLE, 23}, /* 34.152.70.0/23 */
    {0x22984800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.152.72.0/21 */
    {0x22985000u, PROTO_GOOGLE_CLOUD, 23}, /* 34.152.80.0/23 */
    {0x22985200u, PROTO_GOOGLE, 23}, /* 34.152.82.0/23 */
    {0x22985400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.152.84.0/22 */
    {0x22985800u, PROTO_GOOGLE, 21}, /* 34.152.88.0/21 */
    {0x22986000u, PROTO_GOOGLE_CLOUD, 23}, /* 34.152.96.0/23 */
    {0x22986200u, PROTO_GOOGLE_CLOUD, 24}, /* 34.152.98.0/24 */
    {0x22986300u, PROTO_GOOGLE, 24}, /* 34.152.99.0/24 */
    {0x22986400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.152.100.0/22 */
    {0x22986800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.152.104.0/21 */
    {0x22987000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.152.112.0/20 */
    {0x22988000u, PROTO_GOOGLE, 17}, /* 34.152.128.0/17 */
    {0x22990000u, PROTO_GOOGLE, 20}, /* 34.153.0.0/20 */
    {0x22991000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.153.16.0/20 */
    {0x22992000u, PROTO_GOOGLE_CLOUD, 23}, /* 34.153.32.0/23 */
    {0x22992200u, PROTO_GOOGLE, 23}, /* 34.153.34.0/23 */
    {0x22992600u, PROTO_GOOGLE_CLOUD, 24}, /* 34.153.38.0/24 */
    {0x22992700u, PROTO_GOOGLE, 24}, /* 34.153.39.0/24 */
    {0x22992800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.153.40.0/21 */
    {0x22993800u, PROTO_GOOGLE, 23}, /* 34.153.56.0/23 */
    {0x22993a00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.153.58.0/23 */
    {0x22993c00u, PROTO_GOOGLE, 23}, /* 34.153.60.0/23 */
    {0x22993e00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.153.62.0/23 */
    {0x22994000u, PROTO_GOOGLE, 18}, /* 34.153.64.0/18 */
    {0x22998000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.153.128.0/18 */
    {0x2299c000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.153.192.0/19 */
    {0x2299e000u, PROTO_GOOGLE_CLOUD, 23}, /* 34.153.224.0/23 */
    {0x2299e200u, PROTO_GOOGLE, 23}, /* 34.153.226.0/23 */
    {0x2299e600u, PROTO_GOOGLE_CLOUD, 24}, /* 34.153.230.0/24 */
    {0x2299e700u, PROTO_GOOGLE, 24}, /* 34.153.231.0/24 */
    {0x2299e800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.153.232.0/21 */
    {0x2299f800u, PROTO_GOOGLE, 23}, /* 34.153.248.0/23 */
    {0x2299fa00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.153.250.0/23 */
    {0x2299fc00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.153.252.0/22 */
    {0x229a0000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.154.0.0/15 */
    {0x229c0000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.156.0.0/16 */
    {0x229d0000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.157.0.0/21 */
    {0x229d0800u, PROTO_GOOGLE_CLOUD, 23}, /* 34.157.8.0/23 */
    {0x229d0a00u, PROTO_GOOGLE, 23}, /* 34.157.10.0/23 */
    {0x229d0c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.157.12.0/22 */
    {0x229d1000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.157.16.0/20 */
    {0x229d2000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.157.32.0/19 */
    {0x229d4000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.157.64.0/20 */
    {0x229d5000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.157.80.0/22 */
    {0x229d5400u, PROTO_GOOGLE_CLOUD, 23}, /* 34.157.84.0/23 */
    {0x229d5600u, PROTO_GOOGLE, 24}, /* 34.157.86.0/24 */
    {0x229d5700u, PROTO_GOOGLE_CLOUD, 24}, /* 34.157.87.0/24 */
    {0x229d5800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.157.88.0/21 */
    {0x229d6000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.157.96.0/20 */
    {0x229d7000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.157.112.0/21 */
    {0x229d7800u, PROTO_GOOGLE, 24}, /* 34.157.120.0/24 */
    {0x229d7900u, PROTO_GOOGLE_CLOUD, 24}, /* 34.157.121.0/24 */
    {0x229d7b00u, PROTO_GOOGLE_CLOUD, 25}, /* 34.157.123.0/25 */
    {0x229d7b80u, PROTO_GOOGLE, 25}, /* 34.157.123.128/25 */
    {0x229d7c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.157.124.0/22 */
    {0x229d8000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.157.128.0/21 */
    {0x229d8800u, PROTO_GOOGLE_CLOUD, 23}, /* 34.157.136.0/23 */
    {0x229d8a00u, PROTO_GOOGLE, 23}, /* 34.157.138.0/23 */
    {0x229d8c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.157.140.0/22 */
    {0x229d9000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.157.144.0/20 */
    {0x229da000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.157.160.0/19 */
    {0x229dc000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.157.192.0/20 */
    {0x229dd000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.157.208.0/22 */
    {0x229dd400u, PROTO_GOOGLE_CLOUD, 23}, /* 34.157.212.0/23 */
    {0x229dd600u, PROTO_GOOGLE, 24}, /* 34.157.214.0/24 */
    {0x229dd700u, PROTO_GOOGLE_CLOUD, 24}, /* 34.157.215.0/24 */
    {0x229dd800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.157.216.0/21 */
    {0x229de000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.157.224.0/20 */
    {0x229df000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.157.240.0/21 */
    {0x229df800u, PROTO_GOOGLE, 24}, /* 34.157.248.0/24 */
    {0x229df900u, PROTO_GOOGLE_CLOUD, 24}, /* 34.157.249.0/24 */
    {0x229dfa00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.157.250.0/23 */
    {0x229dfc00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.157.252.0/22 */
    {0x229e0000u, PROTO_GOOGLE, 21}, /* 34.158.0.0/21 */
    {0x229e0800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.158.8.0/21 */
    {0x229e1000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.158.16.0/20 */
    {0x229e2000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.158.32.0/19 */
    {0x229e4000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.158.64.0/18 */
    {0x229ec000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.158.192.0/19 */
    {0x229ee000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.158.224.0/20 */
    {0x229ef000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.158.240.0/21 */
    {0x229ef800u, PROTO_GOOGLE, 21}, /* 34.158.248.0/21 */
    {0x229f0000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.159.0.0/16 */
    {0x22a00000u, PROTO_GOOGLE_CLOUD, 14}, /* 34.160.0.0/14 */
    {0x22a40000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.164.0.0/15 */
    {0x22a60000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.166.0.0/16 */
    {0x22a70000u, PROTO_GOOGLE, 16}, /* 34.167.0.0/16 */
    {0x22a80000u, PROTO_GOOGLE_CLOUD, 13}, /* 34.168.0.0/13 */
    {0x22b00000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.176.0.0/16 */
    {0x22b10000u, PROTO_GOOGLE, 19}, /* 34.177.0.0/19 */
    {0x22b12000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.177.32.0/22 */
    {0x22b12400u, PROTO_GOOGLE_CLOUD, 23}, /* 34.177.36.0/23 */
    {0x22b12600u, PROTO_GOOGLE, 23}, /* 34.177.38.0/23 */
    {0x22b12800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.177.40.0/21 */
    {0x22b13800u, PROTO_GOOGLE, 21}, /* 34.177.56.0/21 */
    {0x22b14000u, PROTO_GOOGLE_CLOUD, 23}, /* 34.177.64.0/23 */
    {0x22b14200u, PROTO_GOOGLE_CLOUD, 24}, /* 34.177.66.0/24 */
    {0x22b14300u, PROTO_GOOGLE, 24}, /* 34.177.67.0/24 */
    {0x22b14400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.177.68.0/22 */
    {0x22b14c00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.177.76.0/23 */
    {0x22b14e00u, PROTO_GOOGLE_CLOUD, 25}, /* 34.177.78.0/25 */
    {0x22b14e80u, PROTO_GOOGLE, 25}, /* 34.177.78.128/25 */
    {0x22b14f00u, PROTO_GOOGLE_CLOUD, 24}, /* 34.177.79.0/24 */
    {0x22b15000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.177.80.0/20 */
    {0x22b17000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.177.112.0/21 */
    {0x22b17800u, PROTO_GOOGLE_CLOUD, 22}, /* 34.177.120.0/22 */
    {0x22b17c00u, PROTO_GOOGLE, 22}, /* 34.177.124.0/22 */
    {0x22b18000u, PROTO_GOOGLE, 17}, /* 34.177.128.0/17 */
    {0x22b20000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.178.0.0/15 */
    {0x22b40000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.180.0.0/17 */
    {0x22b48000u, PROTO_GOOGLE, 17}, /* 34.180.128.0/17 */
    {0x22b50000u, PROTO_GOOGLE_CLOUD, 16}, /* 34.181.0.0/16 */
    {0x22b70000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.183.0.0/21 */
    {0x22b70800u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.8.0/23 */
    {0x22b70a00u, PROTO_GOOGLE, 23}, /* 34.183.10.0/23 */
    {0x22b70c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.183.12.0/22 */
    {0x22b71400u, PROTO_GOOGLE, 25}, /* 34.183.20.0/25 */
    {0x22b71480u, PROTO_GOOGLE_CLOUD, 25}, /* 34.183.20.128/25 */
    {0x22b71500u, PROTO_GOOGLE_CLOUD, 24}, /* 34.183.21.0/24 */
    {0x22b71600u, PROTO_GOOGLE, 23}, /* 34.183.22.0/23 */
    {0x22b71800u, PROTO_GOOGLE_CLOUD, 22}, /* 34.183.24.0/22 */
    {0x22b71c00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.28.0/23 */
    {0x22b71e00u, PROTO_GOOGLE, 23}, /* 34.183.30.0/23 */
    {0x22b72000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.183.32.0/22 */
    {0x22b72400u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.36.0/23 */
    {0x22b72600u, PROTO_GOOGLE, 23}, /* 34.183.38.0/23 */
    {0x22b72800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.183.40.0/21 */
    {0x22b73000u, PROTO_GOOGLE, 23}, /* 34.183.48.0/23 */
    {0x22b73200u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.50.0/23 */
    {0x22b73400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.183.52.0/22 */
    {0x22b73c00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.60.0/23 */
    {0x22b73e00u, PROTO_GOOGLE, 23}, /* 34.183.62.0/23 */
    {0x22b74200u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.66.0/23 */
    {0x22b74400u, PROTO_GOOGLE_CLOUD, 22}, /* 34.183.68.0/22 */
    {0x22b74800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.183.72.0/21 */
    {0x22b75000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.183.80.0/20 */
    {0x22b77000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.183.112.0/21 */
    {0x22b77800u, PROTO_GOOGLE_CLOUD, 22}, /* 34.183.120.0/22 */
    {0x22b77c00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.124.0/23 */
    {0x22b77e00u, PROTO_GOOGLE, 23}, /* 34.183.126.0/23 */
    {0x22b78000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.183.128.0/22 */
    {0x22b78400u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.132.0/23 */
    {0x22b78600u, PROTO_GOOGLE, 23}, /* 34.183.134.0/23 */
    {0x22b78800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.183.136.0/21 */
    {0x22b79000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.183.144.0/20 */
    {0x22b7a000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.183.160.0/21 */
    {0x22b7a800u, PROTO_GOOGLE_CLOUD, 22}, /* 34.183.168.0/22 */
    {0x22b7ac00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.183.172.0/23 */
    {0x22b7ae00u, PROTO_GOOGLE, 23}, /* 34.183.174.0/23 */
    {0x22b7b000u, PROTO_GOOGLE, 20}, /* 34.183.176.0/20 */
    {0x22b7c000u, PROTO_GOOGLE, 18}, /* 34.183.192.0/18 */
    {0x22b80000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.184.0.0/21 */
    {0x22b80800u, PROTO_GOOGLE_CLOUD, 23}, /* 34.184.8.0/23 */
    {0x22b80a00u, PROTO_GOOGLE, 23}, /* 34.184.10.0/23 */
    {0x22b80c00u, PROTO_GOOGLE_CLOUD, 22}, /* 34.184.12.0/22 */
    {0x22b81400u, PROTO_GOOGLE, 23}, /* 34.184.20.0/23 */
    {0x22b81600u, PROTO_GOOGLE_CLOUD, 23}, /* 34.184.22.0/23 */
    {0x22b81800u, PROTO_GOOGLE_CLOUD, 22}, /* 34.184.24.0/22 */
    {0x22b81c00u, PROTO_GOOGLE, 23}, /* 34.184.28.0/23 */
    {0x22b81e00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.184.30.0/23 */
    {0x22b82000u, PROTO_GOOGLE_CLOUD, 22}, /* 34.184.32.0/22 */
    {0x22b82400u, PROTO_GOOGLE, 22}, /* 34.184.36.0/22 */
    {0x22b82800u, PROTO_GOOGLE_CLOUD, 21}, /* 34.184.40.0/21 */
    {0x22b83800u, PROTO_GOOGLE_CLOUD, 22}, /* 34.184.56.0/22 */
    {0x22b83c00u, PROTO_GOOGLE, 22}, /* 34.184.60.0/22 */
    {0x22b84000u, PROTO_GOOGLE_CLOUD, 19}, /* 34.184.64.0/19 */
    {0x22b86000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.184.96.0/20 */
    {0x22b87000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.184.112.0/21 */
    {0x22b87800u, PROTO_GOOGLE_CLOUD, 22}, /* 34.184.120.0/22 */
    {0x22b87c00u, PROTO_GOOGLE, 23}, /* 34.184.124.0/23 */
    {0x22b87e00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.184.126.0/23 */
    {0x22b88000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.184.128.0/21 */
    {0x22b88800u, PROTO_GOOGLE_CLOUD, 22}, /* 34.184.136.0/22 */
    {0x22b88c00u, PROTO_GOOGLE, 23}, /* 34.184.140.0/23 */
    {0x22b88e00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.184.142.0/23 */
    {0x22b89000u, PROTO_GOOGLE_CLOUD, 20}, /* 34.184.144.0/20 */
    {0x22b8a000u, PROTO_GOOGLE_CLOUD, 21}, /* 34.184.160.0/21 */
    {0x22b8a800u, PROTO_GOOGLE_CLOUD, 23}, /* 34.184.168.0/23 */
    {0x22b8aa00u, PROTO_GOOGLE_CLOUD, 24}, /* 34.184.170.0/24 */
    {0x22b8ab00u, PROTO_GOOGLE, 24}, /* 34.184.171.0/24 */
    {0x22b8ac00u, PROTO_GOOGLE_CLOUD, 23}, /* 34.184.172.0/23 */
    {0x22b8ae00u, PROTO_GOOGLE, 23}, /* 34.184.174.0/23 */
    {0x22b8b000u, PROTO_GOOGLE, 20}, /* 34.184.176.0/20 */
    {0x22b8c000u, PROTO_GOOGLE, 18}, /* 34.184.192.0/18 */
    {0x22b94000u, PROTO_GOOGLE_CLOUD, 18}, /* 34.185.64.0/18 */
    {0x22b98000u, PROTO_GOOGLE_CLOUD, 17}, /* 34.185.128.0/17 */
    {0x22ba0000u, PROTO_GOOGLE_CLOUD, 15}, /* 34.186.0.0/15 */
    {0x22bc0000u, PROTO_GOOGLE, 14}, /* 34.188.0.0/14 */
    {0x22c00000u, PROTO_AWS, 15}, /* 34.192.0.0/15 */
    {0x22c20000u, PROTO_AWS, 16}, /* 34.194.0.0/16 */
    {0x22c30000u, PROTO_AWS, 17}, /* 34.195.0.0/17 */
    {0x22c38000u, PROTO_AWS, 18}, /* 34.195.128.0/18 */
    {0x22c3c000u, PROTO_AWS, 19}, /* 34.195.192.0/19 */
    {0x22c3e000u, PROTO_AWS, 20}, /* 34.195.224.0/20 */
    {0x22c3f000u, PROTO_AWS, 21}, /* 34.195.240.0/21 */
    {0x22c3f800u, PROTO_AWS, 22}, /* 34.195.248.0/22 */
    {0x22c3fc00u, PROTO_CLOUDFRONT, 24}, /* 34.195.252.0/24 */
    {0x22c3fd00u, PROTO_AWS, 24}, /* 34.195.253.0/24 */
    {0x22c3fe00u, PROTO_AWS, 23}, /* 34.195.254.0/23 */
    {0x22c40000u, PROTO_AWS, 14}, /* 34.196.0.0/14 */
    {0x22c80000u, PROTO_AWS, 13}, /* 34.200.0.0/13 */
    {0x22d80000u, PROTO_AWS, 19}, /* 34.216.0.0/19 */
    {0x22d82000u, PROTO_AWS, 20}, /* 34.216.32.0/20 */
    {0x22d83000u, PROTO_AWS, 23}, /* 34.216.48.0/23 */
    {0x22d83200u, PROTO_AWS, 24}, /* 34.216.50.0/24 */
    {0x22d83300u, PROTO_CLOUDFRONT, 25}, /* 34.216.51.0/25 */
    {0x22d83380u, PROTO_AWS, 25}, /* 34.216.51.128/25 */
    {0x22d83400u, PROTO_AWS, 22}, /* 34.216.52.0/22 */
    {0x22d83800u, PROTO_AWS, 21}, /* 34.216.56.0/21 */
    {0x22d84000u, PROTO_AWS, 18}, /* 34.216.64.0/18 */
    {0x22d88000u, PROTO_AWS, 17}, /* 34.216.128.0/17 */
    {0x22d90000u, PROTO_AWS, 16}, /* 34.217.0.0/16 */
    {0x22da0000u, PROTO_AWS, 15}, /* 34.218.0.0/15 */
    {0x22de0000u, PROTO_AWS, 16}, /* 34.222.0.0/16 */
    {0x22df0000u, PROTO_AWS, 21}, /* 34.223.0.0/21 */
    {0x22df0800u, PROTO_AWS, 22}, /* 34.223.8.0/22 */
    {0x22df0c00u, PROTO_AWS, 25}, /* 34.223.12.0/25 */
    {0x22df0c80u, PROTO_AWS, 26}, /* 34.223.12.128/26 */
    {0x22df0cc0u, PROTO_AWS, 27}, /* 34.223.12.192/27 */
    {0x22df0ce0u, PROTO_CLOUDFRONT, 27}, /* 34.223.12.224/27 */
    {0x22df0d00u, PROTO_AWS, 24}, /* 34.223.13.0/24 */
    {0x22df0e00u, PROTO_AWS, 23}, /* 34.223.14.0/23 */
    {0x22df1000u, PROTO_AWS, 20}, /* 34.223.16.0/20 */
    {0x22df2000u, PROTO_AWS, 19}, /* 34.223.32.0/19 */
    {0x22df4000u, PROTO_AWS, 20}, /* 34.223.64.0/20 */
    {0x22df5000u, PROTO_AWS, 25}, /* 34.223.80.0/25 */
    {0x22df5080u, PROTO_AWS, 26}, /* 34.223.80.128/26 */
    {0x22df50c0u, PROTO_CLOUDFRONT, 26}, /* 34.223.80.192/26 */
    {0x22df5100u, PROTO_AWS, 24}, /* 34.223.81.0/24 */
    {0x22df5200u, PROTO_AWS, 23}, /* 34.223.82.0/23 */
    {0x22df5400u, PROTO_AWS, 22}, /* 34.223.84.0/22 */
    {0x22df5800u, PROTO_AWS, 21}, /* 34.223.88.0/21 */
    {0x22df6000u, PROTO_AWS, 19}, /* 34.223.96.0/19 */
    {0x22df8000u, PROTO_AWS, 17}, /* 34.223.128.0/17 */
    {0x22e00000u, PROTO_AWS, 15}, /* 34.224.0.0/15 */
    {0x22e20000u, PROTO_AWS, 21}, /* 34.226.0.0/21 */
    {0x22e20800u, PROTO_AWS, 22}, /* 34.226.8.0/22 */
    {0x22e20c00u, PROTO_AWS, 23}, /* 34.226.12.0/23 */
    {0x22e20e00u, PROTO_CLOUDFRONT, 24}, /* 34.226.14.0/24 */
    {0x22e20f00u, PROTO_AWS, 24}, /* 34.226.15.0/24 */
    {0x22e21000u, PROTO_AWS, 20}, /* 34.226.16.0/20 */
    {0x22e22000u, PROTO_AWS, 19}, /* 34.226.32.0/19 */
    {0x22e24000u, PROTO_AWS, 18}, /* 34.226.64.0/18 */
    {0x22e28000u, PROTO_AWS, 17}, /* 34.226.128.0/17 */
    {0x22e30000u, PROTO_AWS, 16}, /* 34.227.0.0/16 */
    {0x22e40000u, PROTO_AWS, 14}, /* 34.228.0.0/14 */
    {0x22e80000u, PROTO_AWS, 13}, /* 34.232.0.0/13 */
    {0x22f00000u, PROTO_AWS, 12}, /* 34.240.0.0/12 */
    {0x23000000u, PROTO_UNKNOWN, 0},
    {0x23120000u, PROTO_AWS, 15}, /* 35.18.0.0/15 */
    {0x23140000u, PROTO_UNKNOWN, 0},
    {0x231a0000u, PROTO_AWS, 15}, /* 35.26.0.0/15 */
    {0x231c0000u, PROTO_AWS, 14}, /* 35.28.0.0/14 */
    {0x23200000u, PROTO_UNKNOWN, 0},
    {0x23226000u, PROTO_AWS, 21}, /* 35.34.96.0/21 */
    {0x23226800u, PROTO_AWS, 23}, /* 35.34.104.0/23 */
    {0x23226a00u, PROTO_AWS, 24}, /* 35.34.106.0/24 */
    {0x23226b00u, PROTO_UNKNOWN, 0},
    {0x232a0000u, PROTO_AWS, 15}, /* 35.42.0.0/15 */
    {0x232e0000u, PROTO_UNKNOWN, 0},
    {0x23300000u, PROTO_AWS, 15}, /* 35.48.0.0/15 */
    {0x23320000u, PROTO_UNKNOWN, 0},
    {0x23328000u, PROTO_AWS, 21}, /* 35.50.128.0/21 */
    {0x23328800u, PROTO_UNKNOWN, 0},
    {0x23328900u, PROTO_AWS, 24}, /* 35.50.137.0/24 */
    {0x23328a00u, PROTO_UNKNOWN, 0},
    {0x23328b00u, PROTO_AWS, 24}, /* 35.50.139.0/24 */
    {0x23328c00u, PROTO_UNKNOWN, 0},
    {0x23328d00u, PROTO_AWS, 24}, /* 35.50.141.0/24 */
    {0x23328e00u, PROTO_AWS, 23}, /* 35.50.142.0/23 */
    {0x23329200u, PROTO_UNKNOWN, 0},
    {0x2332a000u, PROTO_AWS, 23}, /* 35.50.160.0/23 */
    {0x2332a200u, PROTO_UNKNOWN, 0},
    {0x2332b000u, PROTO_AWS, 23}, /* 35.50.176.0/23 */
    {0x2332b200u, PROTO_AWS, 24}, /* 35.50.178.0/24 */
    {0x2332b300u, PROTO_UNKNOWN, 0},
    {0x2332c000u, PROTO_AWS, 22}, /* 35.50.192.0/22 */
    {0x2332c400u, PROTO_AWS, 23}, /* 35.50.196.0/23 */
    {0x2332c600u, PROTO_UNKNOWN, 0},
    {0x2332d000u, PROTO_AWS, 22}, /* 35.50.208.0/22 */
    {0x2332d400u, PROTO_AWS, 23}, /* 35.50.212.0/23 */
    {0x2332d600u, PROTO_AWS, 24}, /* 35.50.214.0/24 */
    {0x2332d700u, PROTO_UNKNOWN, 0},
    {0x2332e000u, PROTO_AWS, 24}, /* 35.50.224.0/24 */
    {0x2332e100u, PROTO_UNKNOWN, 0},
    {0x2332e200u, PROTO_AWS, 23}, /* 35.50.226.0/23 */
    {0x2332e400u, PROTO_AWS, 22}, /* 35.50.228.0/22 */
    {0x2332e800u, PROTO_AWS, 21}, /* 35.50.232.0/21 */
    {0x2332f000u, PROTO_AWS, 23}, /* 35.50.240.0/23 */
    {0x2332f200u, PROTO_AWS, 24}, /* 35.50.242.0/24 */
    {0x2332f300u, PROTO_UNKNOWN, 0},
    {0x23340000u, PROTO_AWS, 15}, /* 35.52.0.0/15 */
    {0x23360000u, PROTO_UNKNOWN, 0},
    {0x23361000u, PROTO_AWS, 20}, /* 35.54.16.0/20 */
    {0x23362000u, PROTO_AWS, 19}, /* 35.54.32.0/19 */
    {0x23364000u, PROTO_AWS, 18}, /* 35.54.64.0/18 */
    {0x23368000u, PROTO_UNKNOWN, 0},
    {0x23370000u, PROTO_AWS, 17}, /* 35.55.0.0/17 */
    {0x23378000u, PROTO_UNKNOWN, 0},
    {0x23380000u, PROTO_AWS, 15}, /* 35.56.0.0/15 */
    {0x233a0000u, PROTO_UNKNOWN, 0},
    {0x233c0000u, PROTO_AWS, 15}, /* 35.60.0.0/15 */
    {0x233e0000u, PROTO_UNKNOWN, 0},
    {0x23474000u, PROTO_AWS, 20}, /* 35.71.64.0/20 */
    {0x23475000u, PROTO_UNKNOWN, 0},
    {0x23475a00u, PROTO_AWS, 23}, /* 35.71.90.0/23 */
    {0x23475e00u, PROTO_AWS, 24}, /* 35.71.94.0/24 */
    {0x23475f00u, PROTO_UNKNOWN, 0},
    {0x23476000u, PROTO_AWS, 19}, /* 35.71.96.0/19 */
    {0x23478000u, PROTO_AWS, 17}, /* 35.71.128.0/17 */
    {0x23480000u, PROTO_AWS, 13}, /* 35.72.0.0/13 */
    {0x23580000u, PROTO_AWS, 14}, /* 35.88.0.0/14 */
    {0x235c0000u, PROTO_AWS, 16}, /* 35.92.0.0/16 */
    {0x235d0000u, PROTO_AWS, 17}, /* 35.93.0.0/17 */
    {0x235d8000u, PROTO_AWS, 19}, /* 35.93.128.0/19 */
    {0x235da000u, PROTO_AWS, 21}, /* 35.93.160.0/21 */
    {0x235da800u, PROTO_CLOUDFRONT, 22}, /* 35.93.168.0/22 */
    {0x235dac00u, PROTO_CLOUDFRONT, 23}, /* 35.93.172.0/23 */
    {0x235dae00u, PROTO_AWS, 23}, /* 35.93.174.0/23 */
    {0x235db000u, PROTO_AWS, 20}, /* 35.93.176.0/20 */
    {0x235dc000u, PROTO_AWS, 18}, /* 35.93.192.0/18 */
    {0x235e0000u, PROTO_AWS, 15}, /* 35.94.0.0/15 */
    {0x23600000u, PROTO_UNKNOWN, 0},
    {0x23804000u, PROTO_AWS, 18}, /* 35.128.64.0/18 */
    {0x2380c000u, PROTO_UNKNOWN, 0},
    {0x23980000u, PROTO_AWS, 14}, /* 35.152.0.0/14 */
    {0x239c0000u, PROTO_AWS, 15}, /* 35.156.0.0/15 */
    {0x239e0000u, PROTO_AWS, 17}, /* 35.158.0.0/17 */
    {0x239e8000u, PROTO_AWS, 21}, /* 35.158.128.0/21 */
    {0x239e8800u, PROTO_CLOUDFRONT, 24}, /* 35.158.136.0/24 */
    {0x239e8900u, PROTO_AWS, 24}, /* 35.158.137.0/24 */
    {0x239e8a00u, PROTO_AWS, 23}, /* 35.158.138.0/23 */
    {0x239e8c00u, PROTO_AWS, 22}, /* 35.158.140.0/22 */
    {0x239e9000u, PROTO_AWS, 20}, /* 35.158.144.0/20 */
    {0x239ea000u, PROTO_AWS, 19}, /* 35.158.160.0/19 */
    {0x239ec000u, PROTO_AWS, 18}, /* 35.158.192.0/18 */
    {0x239f0000u, PROTO_AWS, 16}, /* 35.159.0.0/16 */
    {0x23a00000u, PROTO_AWS, 15}, /* 35.160.0.0/15 */
    {0x23a20000u, PROTO_AWS, 19}, /* 35.162.0.0/19 */
    {0x23a22000u, PROTO_AWS, 20}, /* 35.162.32.0/20 */
    {0x23a23000u, PROTO_AWS, 21}, /* 35.162.48.0/21 */
    {0x23a23800u, PROTO_AWS, 22}, /* 35.162.56.0/22 */
    {0x23a23c00u, PROTO_AWS, 23}, /* 35.162.60.0/23 */
    {0x23a23e00u, PROTO_AWS, 24}, /* 35.162.62.0/24 */
    {0x23a23f00u, PROTO_AWS, 25}, /* 35.162.63.0/25 */
    {0x23a23f80u, PROTO_AWS, 26}, /* 35.162.63.128/26 */
    {0x23a23fc0u, PROTO_CLOUDFRONT, 26}, /* 35.162.63.192/26 */
    {0x23a24000u, PROTO_AWS, 18}, /* 35.162.64.0/18 */
    {0x23a28000u, PROTO_AWS, 17}, /* 35.162.128.0/17 */
    {0x23a30000u, PROTO_AWS, 16}, /* 35.163.0.0/16 */
    {0x23a40000u, PROTO_AWS, 15}, /* 35.164.0.0/15 */
    {0x23a60000u, PROTO_AWS, 16}, /* 35.166.0.0/16 */
    {0x23a70000u, PROTO_AWS, 17}, /* 35.167.0.0/17 */
    {0x23a78000u, PROTO_AWS, 19}, /* 35.167.128.0/19 */
    {0x23a7a000u, PROTO_AWS, 20}, /* 35.167.160.0/20 */
    {0x23a7b000u, PROTO_AWS, 21}, /* 35.167.176.0/21 */
    {0x23a7b800u, PROTO_AWS, 22}, /* 35.167.184.0/22 */
    {0x23a7bc00u, PROTO_AWS, 23}, /* 35.167.188.0/23 */
    {0x23a7be00u, PROTO_AWS, 24}, /* 35.167.190.0/24 */
    {0x23a7bf00u, PROTO_AWS, 25}, /* 35.167.191.0/25 */
    {0x23a7bf80u, PROTO_CLOUDFRONT, 26}, /* 35.167.191.128/26 */
    {0x23a7bfc0u, PROTO_AWS, 26}, /* 35.167.191.192/26 */
    {0x23a7c000u, PROTO_AWS, 18}, /* 35.167.192.0/18 */
    {0x23a80000u, PROTO_AWS, 13}, /* 35.168.0.0/13 */
    {0x23b80000u, PROTO_GOOGLE_CLOUD, 15}, /* 35.184.0.0/15 */
    {0x23ba0000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.186.0.0/16 */
    {0x23bb0000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.187.0.0/17 */
    {0x23bb8000u, PROTO_GOOGLE, 20}, /* 35.187.128.0/20 */
    {0x23bb9000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.187.144.0/20 */
    {0x23bba000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.187.160.0/19 */
    {0x23bbc000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.187.192.0/18 */
    {0x23bc0000u, PROTO_GOOGLE_CLOUD, 15}, /* 35.188.0.0/15 */
    {0x23be0000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.190.0.0/18 */
    {0x23be4000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.190.64.0/19 */
    {0x23be6000u, PROTO_GOOGLE, 20}, /* 35.190.96.0/20 */
    {0x23be7000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.190.112.0/20 */
    {0x23be8000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.190.128.0/18 */
    {0x23bec000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.190.192.0/19 */
    {0x23bee000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.190.224.0/20 */
    {0x23bef000u, PROTO_GOOGLE, 20}, /* 35.190.240.0/20 */
    {0x23bf0000u, PROTO_GOOGLE, 16}, /* 35.191.0.0/16 */
    {0x23c00000u, PROTO_GOOGLE_CLOUD, 14}, /* 35.192.0.0/14 */
    {0x23c40000u, PROTO_GOOGLE_CLOUD, 15}, /* 35.196.0.0/15 */
    {0x23c60000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.198.0.0/16 */
    {0x23c70000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.199.0.0/17 */
    {0x23c78000u, PROTO_GOOGLE, 20}, /* 35.199.128.0/20 */
    {0x23c79000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.199.144.0/20 */
    {0x23c7a000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.199.160.0/19 */
    {0x23c7c000u, PROTO_UNKNOWN, 0},
    {0x23c80000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.200.0.0/16 */
    {0x23c90000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.201.0.0/19 */
    {0x23c92000u, PROTO_GOOGLE, 21}, /* 35.201.32.0/21 */
    {0x23c92800u, PROTO_GOOGLE, 24}, /* 35.201.40.0/24 */
    {0x23c92900u, PROTO_GOOGLE_CLOUD, 24}, /* 35.201.41.0/24 */
    {0x23c92a00u, PROTO_GOOGLE, 23}, /* 35.201.42.0/23 */
    {0x23c92c00u, PROTO_GOOGLE, 22}, /* 35.201.44.0/22 */
    {0x23c93000u, PROTO_GOOGLE, 20}, /* 35.201.48.0/20 */
    {0x23c94000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.201.64.0/18 */
    {0x23c98000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.201.128.0/17 */
    {0x23ca0000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.202.0.0/16 */
    {0x23cb0000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.203.0.0/17 */
    {0x23cb8000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.203.128.0/18 */
    {0x23cbc000u, PROTO_GOOGLE, 20}, /* 35.203.192.0/20 */
    {0x23cbd000u, PROTO_GOOGLE, 23}, /* 35.203.208.0/23 */
    {0x23cbd200u, PROTO_GOOGLE_CLOUD, 23}, /* 35.203.210.0/23 */
    {0x23cbd400u, PROTO_GOOGLE_CLOUD, 22}, /* 35.203.212.0/22 */
    {0x23cbdc00u, PROTO_GOOGLE, 22}, /* 35.203.220.0/22 */
    {0x23cbe000u, PROTO_GOOGLE, 21}, /* 35.203.224.0/21 */
    {0x23cbe800u, PROTO_GOOGLE_CLOUD, 21}, /* 35.203.232.0/21 */
    {0x23cbf000u, PROTO_GOOGLE, 20}, /* 35.203.240.0/20 */
    {0x23cc0000u, PROTO_GOOGLE_CLOUD, 15}, /* 35.204.0.0/15 */
    {0x23ce0000u, PROTO_GOOGLE, 21}, /* 35.206.0.0/21 */
    {0x23ce0800u, PROTO_GOOGLE, 23}, /* 35.206.8.0/23 */
    {0x23ce0a00u, PROTO_GOOGLE_CLOUD, 23}, /* 35.206.10.0/23 */
    {0x23ce0c00u, PROTO_GOOGLE, 22}, /* 35.206.12.0/22 */
    {0x23ce1000u, PROTO_GOOGLE, 20}, /* 35.206.16.0/20 */
    {0x23ce2000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.206.32.0/19 */
    {0x23ce4000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.206.64.0/18 */
    {0x23ce8000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.206.128.0/17 */
    {0x23cf0000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.207.0.0/16 */
    {0x23d00000u, PROTO_GOOGLE_CLOUD, 13}, /* 35.208.0.0/13 */
    {0x23d80000u, PROTO_GOOGLE_CLOUD, 15}, /* 35.216.0.0/15 */
    {0x23da0000u, PROTO_GOOGLE, 16}, /* 35.218.0.0/16 */
    {0x23db0000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.219.0.0/17 */
    {0x23db8000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.219.128.0/18 */
    {0x23dbc000u, PROTO_GOOGLE, 19}, /* 35.219.192.0/19 */
    {0x23dbe000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.219.224.0/19 */
    {0x23dc0000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.220.0.0/20 */
    {0x23dc1000u, PROTO_GOOGLE_CLOUD, 21}, /* 35.220.16.0/21 */
    {0x23dc1800u, PROTO_GOOGLE_CLOUD, 22}, /* 35.220.24.0/22 */
    {0x23dc1c00u, PROTO_GOOGLE, 23}, /* 35.220.28.0/23 */
    {0x23dc1e00u, PROTO_GOOGLE, 24}, /* 35.220.30.0/24 */
    {0x23dc1f00u, PROTO_GOOGLE_CLOUD, 24}, /* 35.220.31.0/24 */
    {0x23dc2000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.220.32.0/19 */
    {0x23dc4000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.220.64.0/18 */
    {0x23dc8000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.220.128.0/17 */
    {0x23dd0000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.221.0.0/16 */
    {0x23de0000u, PROTO_GOOGLE_CLOUD, 15}, /* 35.222.0.0/15 */
    {0x23e00000u, PROTO_GOOGLE_CLOUD, 14}, /* 35.224.0.0/14 */
    {0x23e40000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.228.0.0/16 */
    {0x23e50000u, PROTO_GOOGLE, 20}, /* 35.229.0.0/20 */
    {0x23e51000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.229.16.0/20 */
    {0x23e52000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.229.32.0/19 */
    {0x23e54000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.229.64.0/18 */
    {0x23e58000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.229.128.0/17 */
    {0x23e68000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.230.128.0/18 */
    {0x23e6c000u, PROTO_GOOGLE, 19}, /* 35.230.192.0/19 */
    {0x23e6e000u, PROTO_GOOGLE, 20}, /* 35.230.224.0/20 */
    {0x23e6f000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.230.240.0/20 */
    {0x23e70000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.231.0.0/16 */
    {0x23e80000u, PROTO_GOOGLE_CLOUD, 15}, /* 35.232.0.0/15 */
    {0x23ea0000u, PROTO_GOOGLE_CLOUD, 16}, /* 35.234.0.0/16 */
    {0x23eb0000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.235.0.0/17 */
    {0x23eb8000u, PROTO_GOOGLE, 19}, /* 35.235.128.0/19 */
    {0x23eba000u, PROTO_GOOGLE, 21}, /* 35.235.160.0/21 */
    {0x23eba800u, PROTO_GOOGLE, 22}, /* 35.235.168.0/22 */
    {0x23ebac00u, PROTO_GOOGLE_CLOUD, 22}, /* 35.235.172.0/22 */
    {0x23ebb000u, PROTO_GOOGLE, 20}, /* 35.235.176.0/20 */
    {0x23ebd000u, PROTO_GOOGLE, 21}, /* 35.235.208.0/21 */
    {0x23ebd800u, PROTO_GOOGLE_CLOUD, 21}, /* 35.235.216.0/21 */
    {0x23ebe000u, PROTO_GOOGLE, 19}, /* 35.235.224.0/19 */
    {0x23ec0000u, PROTO_GOOGLE_CLOUD, 14}, /* 35.236.0.0/14 */
    {0x23f00000u, PROTO_GOOGLE_CLOUD, 15}, /* 35.240.0.0/15 */
    {0x23f20000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.242.0.0/20 */
    {0x23f21000u, PROTO_GOOGLE_CLOUD, 21}, /* 35.242.16.0/21 */
    {0x23f21800u, PROTO_GOOGLE_CLOUD, 22}, /* 35.242.24.0/22 */
    {0x23f21c00u, PROTO_GOOGLE, 23}, /* 35.242.28.0/23 */
    {0x23f21e00u, PROTO_GOOGLE, 24}, /* 35.242.30.0/24 */
    {0x23f21f00u, PROTO_GOOGLE_CLOUD, 24}, /* 35.242.31.0/24 */
    {0x23f22000u, PROTO_GOOGLE_CLOUD, 19}, /* 35.242.32.0/19 */
    {0x23f24000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.242.64.0/18 */
    {0x23f28000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.242.128.0/17 */
    {0x23f30000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.243.0.0/20 */
    {0x23f31000u, PROTO_GOOGLE, 20}, /* 35.243.16.0/20 */
    {0x23f32000u, PROTO_GOOGLE_CLOUD, 20}, /* 35.243.32.0/20 */
    {0x23f33000u, PROTO_GOOGLE, 21}, /* 35.243.48.0/21 */
    {0x23f33800u, PROTO_GOOGLE_CLOUD, 21}, /* 35.243.56.0/21 */
    {0x23f34000u, PROTO_GOOGLE_CLOUD, 18}, /* 35.243.64.0/18 */
    {0x23f38000u, PROTO_GOOGLE_CLOUD, 17}, /* 35.243.128.0/17 */
    {0x23f40000u, PROTO_GOOGLE_CLOUD, 14}, /* 35.244.0.0/14 */
    {0x23f80000u, PROTO_UNKNOWN, 0},
    {0x23fc0000u, PROTO_GOOGLE_CLOUD, 14}, /* 35.252.0.0/14 */
    {0x24000000u, PROTO_UNKNOWN, 0},
    {0x2467e800u, PROTO_CLOUDFRONT, 25}, /* 36.103.232.0/25 */
    {0x2467e880u, PROTO_CLOUDFRONT, 26}, /* 36.103.232.128/26 */
    {0x2467e8c0u, PROTO_UNKNOWN, 0},
    {0x254db800u, PROTO_NETFLIX, 21}, /* 37.77.184.0/21 */
    {0x254dba00u, PROTO_NETFLIX, 23}, /* 37.77.186.0/23 */
    {0x254dbe00u, PROTO_NETFLIX, 21}, /* 37.77.184.0/21 */
    {0x254dc000u, PROTO_UNKNOWN, 0},
    {0x258b5000u, PROTO_APPLE, 21}, /* 37.139.80.0/21 */
    {0x258b5700u, PROTO_APPLE, 24}, /* 37.139.87.0/24 */
    {0x258b5800u, PROTO_UNKNOWN, 0},
    {0x25cb9d00u, PROTO_AWS, 24}, /* 37.203.157.0/24 */
    {0x25cb9e00u, PROTO_UNKNOWN, 0},
    {0x26487e00u, PROTO_NETFLIX, 24}, /* 38.72.126.0/24 */
    {0x26487f00u, PROTO_UNKNOWN, 0},
    {0x28200000u, PROTO_AWS, 16}, /* 40.32.0.0/16 */
    {0x28210000u, PROTO_UNKNOWN, 0},
    {0x28230000u, PROTO_AWS, 16}, /* 40.35.0.0/16 */
    {0x28240000u, PROTO_UNKNOWN, 0},
    {0x28260000u, PROTO_AWS, 15}, /* 40.38.0.0/15 */
    {0x28280000u, PROTO_UNKNOWN, 0},
    {0x28400000u, PROTO_AZURE, 15}, /* 40.64.0.0/15 */
    {0x28420000u, PROTO_UNKNOWN, 0},
    {0x28422000u, PROTO_AZURE, 19}, /* 40.66.32.0/19 */
    {0x28424000u, PROTO_UNKNOWN, 0},
    {0x28427800u, PROTO_AZURE, 21}, /* 40.66.120.0/21 */
    {0x28428000u, PROTO_UNKNOWN, 0},
    {0x28430000u, PROTO_AZURE, 19}, /* 40.67.0.0/19 */
    {0x28432000u, PROTO_UNKNOWN, 0},
    {0x28432800u, PROTO_AZURE, 21}, /* 40.67.40.0/21 */
    {0x28433000u, PROTO_AZURE, 20}, /* 40.67.48.0/20 */
    {0x28434000u, PROTO_AZURE, 19}, /* 40.67.64.0/19 */
    {0x28436000u, PROTO_AZURE, 20}, /* 40.67.96.0/20 */
    {0x28437000u, PROTO_UNKNOWN, 0},
    {0x28437800u, PROTO_AZURE, 21}, /* 40.67.120.0/21 */
    {0x28438000u, PROTO_AZURE, 17}, /* 40.67.128.0/17 */
    {0x28440000u, PROTO_AZURE, 16}, /* 40.68.0.0/16 */
    {0x28450000u, PROTO_AZURE, 17}, /* 40.69.0.0/17 */
    {0x28458000u, PROTO_AZURE, 18}, /* 40.69.128.0/18 */
    {0x2845c000u, PROTO_AZURE, 19}, /* 40.69.192.0/19 */
    {0x2845e000u, PROTO_UNKNOWN, 0},
    {0x28460000u, PROTO_AZURE, 15}, /* 40.70.0.0/15 */
    {0x28480000u, PROTO_UNKNOWN, 0},
    {0x284a0000u, PROTO_AZURE, 15}, /* 40.74.0.0/15 */
    {0x284c0000u, PROTO_AZURE, 16}, /* 40.76.0.0/16 */
    {0x284d0000u, PROTO_AZURE, 17}, /* 40.77.0.0/17 */
    {0x284d8000u, PROTO_AZURE, 19}, /* 40.77.128.0/19 */
    {0x284da000u, PROTO_AZURE, 22}, /* 40.77.160.0/22 */
    {0x284da400u, PROTO_AZURE, 23}, /* 40.77.164.0/23 */
    {0x284da600u, PROTO_AZURE, 25}, /* 40.77.166.0/25 */
    {0x284da680u, PROTO_AZURE, 28}, /* 40.77.166.128/28 */
    {0x284da690u, PROTO_UNKNOWN, 0},
    {0x284da6a0u, PROTO_AZURE, 27}, /* 40.77.166.160/27 */
    {0x284da6c0u, PROTO_AZURE, 26}, /* 40.77.166.192/26 */
    {0x284da700u, PROTO_AZURE, 24}, /* 40.77.167.0/24 */
    {0x284da800u, PROTO_AZURE, 22}, /* 40.77.168.0/22 */
    {0x284dac00u, PROTO_AZURE, 23}, /* 40.77.172.0/23 */
    {0x284dae00u, PROTO_AZURE, 24}, /* 40.77.174.0/24 */
    {0x284daf00u, PROTO_AZURE, 25}, /* 40.77.175.0/25 */
    {0x284daf80u, PROTO_AZURE, 26}, /* 40.77.175.128/26 */
    {0x284dafc0u, PROTO_AZURE, 27}, /* 40.77.175.192/27 */
    {0x284dafe0u, PROTO_UNKNOWN, 0},
    {0x284daff0u, PROTO_AZURE, 28}, /* 40.77.175.240/28 */
    {0x284db000u, PROTO_AZURE, 20}, /* 40.77.176.0/20 */
    {0x284dc000u, PROTO_AZURE, 21}, /* 40.77.192.0/21 */
    {0x284dc800u, PROTO_AZURE, 23}, /* 40.77.200.0/23 */
    {0x284dca00u, PROTO_AZURE, 24}, /* 40.77.202.0/24 */
    {0x284dcb00u, PROTO_UNKNOWN, 0},
    {0x284de000u, PROTO_AZURE, 20}, /* 40.77.224.0/20 */
    {0x284df000u, PROTO_AZURE, 22}, /* 40.77.240.0/22 */
    {0x284df400u, PROTO_AZURE, 25}, /* 40.77.244.0/25 */
    {0x284df480u, PROTO_UNKNOWN, 0},
    {0x284df500u, PROTO_AZURE, 24}, /* 40.77.245.0/24 */
    {0x284df600u, PROTO_AZURE, 23}, /* 40.77.246.0/23 */
    {0x284df800u, PROTO_AZURE, 21}, /* 40.77.248.0/21 */
    {0x284e0000u, PROTO_AZURE, 17}, /* 40.78.0.0/17 */
    {0x284e8000u, PROTO_AZURE, 18}, /* 40.78.128.0/18 */
    {0x284ec000u, PROTO_AZURE, 20}, /* 40.78.192.0/20 */
    {0x284ed000u, PROTO_AZURE, 27}, /* 40.78.208.0/27 */
    {0x284ed020u, PROTO_AZURE, 30}, /* 40.78.208.32/30 */
    {0x284ed024u, PROTO_UNKNOWN, 0},
    {0x284ed030u, PROTO_AZURE, 28}, /* 40.78.208.48/28 */
    {0x284ed040u, PROTO_AZURE, 27}, /* 40.78.208.64/27 */
    {0x284ed060u, PROTO_UNKNOWN, 0},
    {0x284ed080u, PROTO_AZURE, 26}, /* 40.78.208.128/26 */
    {0x284ed0c0u, PROTO_UNKNOWN, 0},
    {0x284ed100u, PROTO_AZURE, 24}, /* 40.78.209.0/24 */
    {0x284ed200u, PROTO_AZURE, 23}, /* 40.78.210.0/23 */
    {0x284ed400u, PROTO_AZURE, 22}, /* 40.78.212.0/22 */
    {0x284ed800u, PROTO_AZURE, 21}, /* 40.78.216.0/21 */
    {0x284ee000u, PROTO_AZURE, 19}, /* 40.78.224.0/19 */
    {0x284f0000u, PROTO_AZURE, 16}, /* 40.79.0.0/16 */
    {0x28500000u, PROTO_AZURE, 18}, /* 40.80.0.0/18 */
    {0x28504000u, PROTO_AZURE, 19}, /* 40.80.64.0/19 */
    {0x28506000u, PROTO_AZURE, 20}, /* 40.80.96.0/20 */
    {0x28507000u, PROTO_UNKNOWN, 0},
    {0x28509000u, PROTO_AZURE, 20}, /* 40.80.144.0/20 */
    {0x2850a000u, PROTO_AZURE, 24}, /* 40.80.160.0/24 */
    {0x2850a100u, PROTO_AZURE, 28}, /* 40.80.161.0/28 */
    {0x2850a110u, PROTO_UNKNOWN, 0},
    {0x2850a800u, PROTO_AZURE, 21}, /* 40.80.168.0/21 */
    {0x2850b000u, PROTO_AZURE, 20}, /* 40.80.176.0/20 */
    {0x2850c000u, PROTO_AZURE, 18}, /* 40.80.192.0/18 */
    {0x28510000u, PROTO_AZURE, 16}, /* 40.81.0.0/16 */
    {0x28520000u, PROTO_AZURE, 19}, /* 40.82.0.0/19 */
    {0x28522000u, PROTO_AZURE, 20}, /* 40.82.32.0/20 */
    {0x28523000u, PROTO_AZURE, 22}, /* 40.82.48.0/22 */
    {0x28523400u, PROTO_UNKNOWN, 0},
    {0x28523c00u, PROTO_AZURE, 22}, /* 40.82.60.0/22 */
    {0x28524000u, PROTO_AZURE, 21}, /* 40.82.64.0/21 */
    {0x28524800u, PROTO_UNKNOWN, 0},
    {0x28525000u, PROTO_AZURE, 22}, /* 40.82.80.0/22 */
    {0x28525400u, PROTO_UNKNOWN, 0},
    {0x28525c00u, PROTO_AZURE, 22}, /* 40.82.92.0/22 */
    {0x28526400u, PROTO_UNKNOWN, 0},
    {0x28528000u, PROTO_AZURE, 17}, /* 40.82.128.0/17 */
    {0x28530000u, PROTO_AZURE, 16}, /* 40.83.0.0/16 */
    {0x28540000u, PROTO_AZURE, 15}, /* 40.84.0.0/15 */
    {0x28560000u, PROTO_AZURE, 16}, /* 40.86.0.0/16 */
    {0x28570000u, PROTO_AZURE, 17}, /* 40.87.0.0/17 */
    {0x28578000u, PROTO_AZURE, 18}, /* 40.87.128.0/18 */
    {0x2857c000u, PROTO_AZURE, 19}, /* 40.87.192.0/19 */
    {0x2857e000u, PROTO_AZURE, 20}, /* 40.87.224.0/20 */
    {0x2857f000u, PROTO_UNKNOWN, 0},
    {0x28580000u, PROTO_AZURE, 15}, /* 40.88.0.0/15 */
    {0x285a0000u, PROTO_UNKNOWN, 0},
    {0x285a0800u, PROTO_AZURE, 21}, /* 40.90.8.0/21 */
    {0x285a1000u, PROTO_AZURE, 20}, /* 40.90.16.0/20 */
    {0x285a2000u, PROTO_UNKNOWN, 0},
    {0x285a8000u, PROTO_AZURE, 17}, /* 40.90.128.0/17 */
    {0x285b0000u, PROTO_AZURE, 16}, /* 40.91.0.0/16 */
    {0x285c0000u, PROTO_UNKNOWN, 0},
    {0x285d0000u, PROTO_AZURE, 16}, /* 40.93.0.0/16 */
    {0x285e0000u, PROTO_UNKNOWN, 0},
    {0x28602e00u, PROTO_AZURE, 24}, /* 40.96.46.0/24 */
    {0x28602f00u, PROTO_UNKNOWN, 0},
    {0x28603200u, PROTO_AZURE, 24}, /* 40.96.50.0/24 */
    {0x28603300u, PROTO_UNKNOWN, 0},
    {0x28603400u, PROTO_AZURE, 24}, /* 40.96.52.0/24 */
    {0x28603500u, PROTO_UNKNOWN, 0},
    {0x28603700u, PROTO_AZURE, 24}, /* 40.96.55.0/24 */
    {0x28603800u, PROTO_UNKNOWN, 0},
    {0x28603d00u, PROTO_AZURE, 24}, /* 40.96.61.0/24 */
    {0x28603e00u, PROTO_UNKNOWN, 0},
    {0x28603f00u, PROTO_AZURE, 24}, /* 40.96.63.0/24 */
    {0x28604000u, PROTO_UNKNOWN, 0},
    {0x2860ff00u, PROTO_AZURE, 24}, /* 40.96.255.0/24 */
    {0x28610000u, PROTO_UNKNOWN, 0},
    {0x28610400u, PROTO_AZURE, 22}, /* 40.97.4.0/22 */
    {0x28610800u, PROTO_UNKNOWN, 0},
    {0x28610c00u, PROTO_AZURE, 22}, /* 40.97.12.0/22 */
    {0x28611000u, PROTO_UNKNOWN, 0},
    {0x28611400u, PROTO_AZURE, 22}, /* 40.97.20.0/22 */
    {0x28611800u, PROTO_UNKNOWN, 0},
    {0x28612000u, PROTO_AZURE, 22}, /* 40.97.32.0/22 */
    {0x28612400u, PROTO_UNKNOWN, 0},
    {0x28612c00u, PROTO_AZURE, 22}, /* 40.97.44.0/22 */
    {0x28613000u, PROTO_UNKNOWN, 0},
    {0x28613400u, PROTO_AZURE, 22}, /* 40.97.52.0/22 */
    {0x28613800u, PROTO_UNKNOWN, 0},
    {0x28613c00u, PROTO_AZURE, 22}, /* 40.97.60.0/22 */
    {0x28614000u, PROTO_UNKNOWN, 0},
    {0x28614800u, PROTO_AZURE, 24}, /* 40.97.72.0/24 */
    {0x28614900u, PROTO_AZURE, 25}, /* 40.97.73.0/25 */
    {0x28614980u, PROTO_AZURE, 26}, /* 40.97.73.128/26 */
    {0x286149c0u, PROTO_UNKNOWN, 0},
    {0x28620000u, PROTO_AZURE, 22}, /* 40.98.0.0/22 */
    {0x28620400u, PROTO_AZURE, 26}, /* 40.98.4.0/26 */
    {0x28620440u, PROTO_UNKNOWN, 0},
    {0x28620500u, PROTO_AZURE, 24}, /* 40.98.5.0/24 */
    {0x28620600u, PROTO_AZURE, 23}, /* 40.98.6.0/23 */
    {0x28620800u, PROTO_AZURE, 22}, /* 40.98.8.0/22 */
    {0x28620c00u, PROTO_AZURE, 24}, /* 40.98.12.0/24 */
    {0x28620d00u, PROTO_UNKNOWN, 0},
    {0x28621000u, PROTO_AZURE, 24}, /* 40.98.16.0/24 */
    {0x28621100u, PROTO_UNKNOWN, 0},
    {0x28621200u, PROTO_AZURE, 23}, /* 40.98.18.0/23 */
    {0x28621400u, PROTO_AZURE, 22}, /* 40.98.20.0/22 */
    {0x28621800u, PROTO_AZURE, 21}, /* 40.98.24.0/21 */
    {0x28622000u, PROTO_UNKNOWN, 0},
    {0x28640400u, PROTO_AZURE, 22}, /* 40.100.4.0/22 */
    {0x28640800u, PROTO_UNKNOWN, 0},
    {0x28641800u, PROTO_AZURE, 22}, /* 40.100.24.0/22 */
    {0x28641c00u, PROTO_UNKNOWN, 0},
    {0x28642400u, PROTO_AZURE, 22}, /* 40.100.36.0/22 */
    {0x28642800u, PROTO_UNKNOWN, 0},
    {0x28642c80u, PROTO_AZURE, 26}, /* 40.100.44.128/26 */
    {0x28642cc0u, PROTO_UNKNOWN, 0},
    {0x28642d40u, PROTO_AZURE, 26}, /* 40.100.45.64/26 */
    {0x28642d80u, PROTO_UNKNOWN, 0},
    {0x28643a00u, PROTO_AZURE, 23}, /* 40.100.58.0/23 */
    {0x28643c00u, PROTO_AZURE, 22}, /* 40.100.60.0/22 */
    {0x28644000u, PROTO_AZURE, 21}, /* 40.100.64.0/21 */
    {0x28644800u, PROTO_AZURE, 24}, /* 40.100.72.0/24 */
    {0x28644900u, PROTO_AZURE, 25}, /* 40.100.73.0/25 */
    {0x28644980u, PROTO_AZURE, 26}, /* 40.100.73.128/26 */
    {0x286449c0u, PROTO_UNKNOWN, 0},
    {0x28645000u, PROTO_AZURE, 24}, /* 40.100.80.0/24 */
    {0x28645100u, PROTO_UNKNOWN, 0},
    {0x28650000u, PROTO_AZURE, 22}, /* 40.101.0.0/22 */
    {0x28650400u, PROTO_UNKNOWN, 0},
    {0x28651400u, PROTO_AZURE, 22}, /* 40.101.20.0/22 */
    {0x28651c00u, PROTO_UNKNOWN, 0},
    {0x28653800u, PROTO_AZURE, 22}, /* 40.101.56.0/22 */
    {0x28653c00u, PROTO_UNKNOWN, 0},
    {0x28657000u, PROTO_AZURE, 22}, /* 40.101.112.0/22 */
    {0x28657400u, PROTO_AZURE, 25}, /* 40.101.116.0/25 */
    {0x28657480u, PROTO_AZURE, 26}, /* 40.101.116.128/26 */
    {0x286574c0u, PROTO_UNKNOWN, 0},
    {0x28661000u, PROTO_AZURE, 22}, /* 40.102.16.0/22 */
    {0x28661400u, PROTO_UNKNOWN, 0},
    {0x28661800u, PROTO_AZURE, 25}, /* 40.102.24.0/25 */
    {0x28661880u, PROTO_AZURE, 26}, /* 40.102.24.128/26 */
    {0x286618c0u, PROTO_UNKNOWN, 0},
    {0x286b0100u, PROTO_AZURE, 24}, /* 40.107.1.0/24 */
    {0x286b0200u, PROTO_AZURE, 23}, /* 40.107.2.0/23 */
    {0x286b0600u, PROTO_UNKNOWN, 0},
    {0x286b0a00u, PROTO_AZURE, 23}, /* 40.107.10.0/23 */
    {0x286b0c00u, PROTO_AZURE, 24}, /* 40.107.12.0/24 */
    {0x286b0d00u, PROTO_UNKNOWN, 0},
    {0x286b2600u, PROTO_AZURE, 23}, /* 40.107.38.0/23 */
    {0x286b2800u, PROTO_AZURE, 21}, /* 40.107.40.0/21 */
    {0x286b3000u, PROTO_AZURE, 20}, /* 40.107.48.0/20 */
    {0x286b4000u, PROTO_UNKNOWN, 0},
    {0x286b4200u, PROTO_AZURE, 23}, /* 40.107.66.0/23 */
    {0x286b4600u, PROTO_UNKNOWN, 0},
    {0x286b4800u, PROTO_AZURE, 24}, /* 40.107.72.0/24 */
    {0x286b4900u, PROTO_UNKNOWN, 0},
    {0x286b4a00u, PROTO_AZURE, 23}, /* 40.107.74.0/23 */
    {0x286b4c00u, PROTO_AZURE, 24}, /* 40.107.76.0/24 */
    {0x286b4d00u, PROTO_UNKNOWN, 0},
    {0x286b8200u, PROTO_AZURE, 24}, /* 40.107.130.0/24 */
    {0x286b8300u, PROTO_UNKNOWN, 0},
    {0x286b8400u, PROTO_AZURE, 24}, /* 40.107.132.0/24 */
    {0x286b8500u, PROTO_UNKNOWN, 0},
    {0x286b8900u, PROTO_AZURE, 24}, /* 40.107.137.0/24 */
    {0x286b8a00u, PROTO_AZURE, 23}, /* 40.107.138.0/23 */
    {0x286b8e00u, PROTO_UNKNOWN, 0},
    {0x286b9000u, PROTO_AZURE, 20}, /* 40.107.144.0/20 */
    {0x286bb000u, PROTO_AZURE, 22}, /* 40.107.176.0/22 */
    {0x286bb400u, PROTO_AZURE, 24}, /* 40.107.180.0/24 */
    {0x286bb500u, PROTO_UNKNOWN, 0},
    {0x286bc000u, PROTO_AZURE, 22}, /* 40.107.192.0/22 */
    {0x286bc400u, PROTO_UNKNOWN, 0},
    {0x286bc500u, PROTO_AZURE, 24}, /* 40.107.197.0/24 */
    {0x286bc600u, PROTO_AZURE, 23}, /* 40.107.198.0/23 */
    {0x286bc800u, PROTO_AZURE, 21}, /* 40.107.200.0/21 */
    {0x286bd000u, PROTO_AZURE, 23}, /* 40.107.208.0/23 */
    {0x286bd200u, PROTO_AZURE, 24}, /* 40.107.210.0/24 */
    {0x286bd300u, PROTO_UNKNOWN, 0},
    {0x28700000u, PROTO_AZURE, 19}, /* 40.112.0.0/19 */
    {0x28702000u, PROTO_UNKNOWN, 0},
    {0x28702400u, PROTO_AZURE, 23}, /* 40.112.36.0/23 */
    {0x28702600u, PROTO_UNKNOWN, 0},
    {0x287026c0u, PROTO_AZURE, 26}, /* 40.112.38.192/26 */
    {0x28702700u, PROTO_UNKNOWN, 0},
    {0x28703000u, PROTO_AZURE, 20}, /* 40.112.48.0/20 */
    {0x28704000u, PROTO_AZURE, 18}, /* 40.112.64.0/18 */
    {0x28708000u, PROTO_AZURE, 17}, /* 40.112.128.0/17 */
    {0x28710000u, PROTO_AZURE, 16}, /* 40.113.0.0/16 */
    {0x28720000u, PROTO_AZURE, 15}, /* 40.114.0.0/15 */
    {0x28740000u, PROTO_AZURE, 14}, /* 40.116.0.0/14 */
    {0x28780000u, PROTO_AZURE, 17}, /* 40.120.0.0/17 */
    {0x28788000u, PROTO_AZURE, 18}, /* 40.120.128.0/18 */
    {0x2878c000u, PROTO_UNKNOWN, 0},
    {0x28790000u, PROTO_AZURE, 16}, /* 40.121.0.0/16 */
    {0x287a0000u, PROTO_AZURE, 15}, /* 40.122.0.0/15 */
    {0x287c0000u, PROTO_AZURE, 16}, /* 40.124.0.0/16 */
    {0x287d0000u, PROTO_AZURE, 17}, /* 40.125.0.0/17 */
    {0x287d8000u, PROTO_UNKNOWN, 0},
    {0x287e0000u, PROTO_AZURE, 18}, /* 40.126.0.0/18 */
    {0x287e4000u, PROTO_UNKNOWN, 0},
    {0x287e8000u, PROTO_AZURE, 17}, /* 40.126.128.0/17 */
    {0x287f0000u, PROTO_AZURE, 19}, /* 40.127.0.0/19 */
    {0x287f2000u, PROTO_AZURE, 24}, /* 40.127.32.0/24 */
    {0x287f2100u, PROTO_UNKNOWN, 0},
    {0x287f4000u, PROTO_AZURE, 19}, /* 40.127.64.0/19 */
    {0x287f6000u, PROTO_AZURE, 20}, /* 40.127.96.0/20 */
    {0x287f7000u, PROTO_UNKNOWN, 0},
    {0x287f8000u, PROTO_AZURE, 17}, /* 40.127.128.0/17 */
    {0x28800000u, PROTO_UNKNOWN, 0},
    {0x288ad800u, PROTO_AWS, 22}, /* 40.138.216.0/22 */
    {0x288adc00u, PROTO_UNKNOWN, 0},
    {0x288f4000u, PROTO_AWS, 21}, /* 40.143.64.0/21 */
    {0x288f4800u, PROTO_UNKNOWN, 0},
    {0x28a30000u, PROTO_AWS, 22}, /* 40.163.0.0/22 */
    {0x28a30400u, PROTO_UNKNOWN, 0},
    {0x28a40000u, PROTO_AWS, 14}, /* 40.164.0.0/14 */
    {0x28a80000u, PROTO_UNKNOWN, 0},
    {0x28a8e000u, PROTO_AWS, 21}, /* 40.168.224.0/21 */
    {0x28a8e800u, PROTO_UNKNOWN, 0},
    {0x28a8ff00u, PROTO_AWS, 24}, /* 40.168.255.0/24 */
    {0x28a90000u, PROTO_UNKNOWN, 0},
    {0x28ac0000u, PROTO_AWS, 14}, /* 40.172.0.0/14 */
    {0x28b40000u, PROTO_AWS, 15}, /* 40.180.0.0/15 */
    {0x28b60000u, PROTO_UNKNOWN, 0},
    {0x28ba0000u, PROTO_AWS, 15}, /* 40.186.0.0/15 */
    {0x28bc0000u, PROTO_AWS, 16}, /* 40.188.0.0/16 */
    {0x28bd0000u, PROTO_UNKNOWN, 0},
    {0x28c00000u, PROTO_AWS, 14}, /* 40.192.0.0/14 */
    {0x28c40000u, PROTO_UNKNOWN, 0},
    {0x28c90000u, PROTO_AWS, 16}, /* 40.201.0.0/16 */
    {0x28ca0000u, PROTO_UNKNOWN, 0},
    {0x28eb4000u, PROTO_AWS, 18}, /* 40.235.64.0/18 */
    {0x28eb8000u, PROTO_AWS, 17}, /* 40.235.128.0/17 */
    {0x28ec0000u, PROTO_UNKNOWN, 0},
    {0x28ee0000u, PROTO_AWS, 15}, /* 40.238.0.0/15 */
    {0x28f00000u, PROTO_UNKNOWN, 0},
    {0x2bc00000u, PROTO_AWS, 16}, /* 43.192.0.0/16 */
    {0x2bc10000u, PROTO_AWS, 18}, /* 43.193.0.0/18 */
    {0x2bc14000u, PROTO_AWS, 22}, /* 43.193.64.0/22 */
    {0x2bc14400u, PROTO_UNKNOWN, 0},
    {0x2bc20000u, PROTO_AWS, 20}, /* 43.194.0.0/20 */
    {0x2bc21000u, PROTO_AWS, 24}, /* 43.194.16.0/24 */
    {0x2bc21100u, PROTO_UNKNOWN, 0},
    {0x2bc30000u, PROTO_AWS, 20}, /* 43.195.0.0/20 */
    {0x2bc31000u, PROTO_AWS, 22}, /* 43.195.16.0/22 */
    {0x2bc31400u, PROTO_AWS, 23}, /* 43.195.20.0/23 */
    {0x2bc31600u, PROTO_UNKNOWN, 0},
    {0x2bc40000u, PROTO_AWS, 16}, /* 43.196.0.0/16 */
    {0x2bc50000u, PROTO_UNKNOWN, 0},
    {0x2bc60000u, PROTO_AWS, 15}, /* 43.198.0.0/15 */
    {0x2bc80000u, PROTO_AWS, 13}, /* 43.200.0.0/13 */
    {0x2bd80000u, PROTO_AWS, 15}, /* 43.216.0.0/15 */
    {0x2bda0000u, PROTO_AWS, 19}, /* 43.218.0.0/19 */
    {0x2bda2000u, PROTO_AWS, 20}, /* 43.218.32.0/20 */
    {0x2bda3000u, PROTO_AWS, 21}, /* 43.218.48.0/21 */
    {0x2bda3800u, PROTO_AWS, 26}, /* 43.218.56.0/26 */
    {0x2bda3840u, PROTO_CLOUDFRONT, 26}, /* 43.218.56.64/26 */
    {0x2bda3880u, PROTO_CLOUDFRONT, 25}, /* 43.218.56.128/25 */
    {0x2bda3900u, PROTO_AWS, 24}, /* 43.218.57.0/24 */
    {0x2bda3a00u, PROTO_AWS, 23}, /* 43.218.58.0/23 */
    {0x2bda3c00u, PROTO_AWS, 22}, /* 43.218.60.0/22 */
    {0x2bda4400u, PROTO_AWS, 23}, /* 43.218.68.0/23 */
    {0x2bda4600u, PROTO_AWS, 24}, /* 43.218.70.0/24 */
    {0x2bda4700u, PROTO_CLOUDFRONT, 26}, /* 43.218.71.0/26 */
    {0x2bda4740u, PROTO_AWS, 26}, /* 43.218.71.64/26 */
    {0x2bda4780u, PROTO_AWS, 25}, /* 43.218.71.128/25 */
    {0x2bda4800u, PROTO_AWS, 21}, /* 43.218.72.0/21 */
    {0x2bda5000u, PROTO_AWS, 20}, /* 43.218.80.0/20 */
    {0x2bda6000u, PROTO_AWS, 19}, /* 43.218.96.0/19 */
    {0x2bda8000u, PROTO_AWS, 17}, /* 43.218.128.0/17 */
    {0x2bdb0000u, PROTO_UNKNOWN, 0},
    {0x2bdc0000u, PROTO_AWS, 15}, /* 43.220.0.0/15 */
    {0x2bde0000u, PROTO_UNKNOWN, 0},
    {0x2be21b00u, PROTO_AWS, 24}, /* 43.226.27.0/24 */
    {0x2be21c00u, PROTO_UNKNOWN, 0},
    {0x2bf92c00u, PROTO_AWS, 22}, /* 43.249.44.0/22 */
    {0x2bf93000u, PROTO_UNKNOWN, 0},
    {0x2bf94800u, PROTO_FASTLY, 22}, /* 43.249.72.0/22 */
    {0x2bf94c00u, PROTO_UNKNOWN, 0},
    {0x2bfac000u, PROTO_AWS, 23}, /* 43.250.192.0/23 */
    {0x2bfac200u, PROTO_UNKNOWN, 0},
    {0x2cc00000u, PROTO_AWS, 12}, /* 44.192.0.0/12 */
    {0x2cd00000u, PROTO_AWS, 13}, /* 44.208.0.0/13 */
    {0x2cd80000u, PROTO_AWS, 14}, /* 44.216.0.0/14 */
    {0x2cdc0000u, PROTO_AWS, 17}, /* 44.220.0.0/17 */
    {0x2cdc8000u, PROTO_AWS, 18}, /* 44.220.128.0/18 */
    {0x2cdcc000u, PROTO_AWS, 23}, /* 44.220.192.0/23 */
    {0x2cdcc200u, PROTO_CLOUDFRONT, 23}, /* 44.220.194.0/23 */
    {0x2cdcc400u, PROTO_CLOUDFRONT, 22}, /* 44.220.196.0/22 */
    {0x2cdccc00u, PROTO_AWS, 22}, /* 44.220.204.0/22 */
    {0x2cdcd000u, PROTO_AWS, 20}, /* 44.220.208.0/20 */
    {0x2cdce000u, PROTO_AWS, 19}, /* 44.220.224.0/19 */
    {0x2cdd0000u, PROTO_AWS, 16}, /* 44.221.0.0/16 */
    {0x2cde0000u, PROTO_AWS, 18}, /* 44.222.0.0/18 */
    {0x2cde4000u, PROTO_AWS, 23}, /* 44.222.64.0/23 */
    {0x2cde4200u, PROTO_CLOUDFRONT, 24}, /* 44.222.66.0/24 */
    {0x2cde4300u, PROTO_AWS, 24}, /* 44.222.67.0/24 */
    {0x2cde4400u, PROTO_AWS, 22}, /* 44.222.68.0/22 */
    {0x2cde4800u, PROTO_AWS, 21}, /* 44.222.72.0/21 */
    {0x2cde5000u, PROTO_AWS, 20}, /* 44.222.80.0/20 */
    {0x2cde6000u, PROTO_AWS, 19}, /* 44.222.96.0/19 */
    {0x2cde8000u, PROTO_AWS, 17}, /* 44.222.128.0/17 */
    {0x2cdf0000u, PROTO_AWS, 16}, /* 44.223.0.0/16 */
    {0x2ce00000u, PROTO_AWS, 15}, /* 44.224.0.0/15 */
    {0x2ce20000u, PROTO_AWS, 16}, /* 44.226.0.0/16 */
    {0x2ce30000u, PROTO_AWS, 17}, /* 44.227.0.0/17 */
    {0x2ce38000u, PROTO_AWS, 19}, /* 44.227.128.0/19 */
    {0x2ce3a000u, PROTO_AWS, 20}, /* 44.227.160.0/20 */
    {0x2ce3b000u, PROTO_AWS, 23}, /* 44.227.176.0/23 */
    {0x2ce3b200u, PROTO_CLOUDFRONT, 24}, /* 44.227.178.0/24 */
    {0x2ce3b300u, PROTO_AWS, 24}, /* 44.227.179.0/24 */
    {0x2ce3b400u, PROTO_AWS, 22}, /* 44.227.180.0/22 */
    {0x2ce3b800u, PROTO_AWS, 21}, /* 44.227.184.0/21 */
    {0x2ce3c000u, PROTO_AWS, 18}, /* 44.227.192.0/18 */
    {0x2ce40000u, PROTO_AWS, 14}, /* 44.228.0.0/14 */
    {0x2ce80000u, PROTO_AWS, 15}, /* 44.232.0.0/15 */
    {0x2cea0000u, PROTO_AWS, 18}, /* 44.234.0.0/18 */
    {0x2cea4000u, PROTO_AWS, 20}, /* 44.234.64.0/20 */
    {0x2cea5000u, PROTO_AWS, 21}, /* 44.234.80.0/21 */
    {0x2cea5800u, PROTO_AWS, 23}, /* 44.234.88.0/23 */
    {0x2cea5a00u, PROTO_AWS, 25}, /* 44.234.90.0/25 */
    {0x2cea5a80u, PROTO_AWS, 26}, /* 44.234.90.128/26 */
    {0x2cea5ac0u, PROTO_AWS, 27}, /* 44.234.90.192/27 */
    {0x2cea5ae0u, PROTO_AWS, 28}, /* 44.234.90.224/28 */
    {0x2cea5af0u, PROTO_AWS, 29}, /* 44.234.90.240/29 */
    {0x2cea5af8u, PROTO_AWS, 30}, /* 44.234.90.248/30 */
    {0x2cea5afcu, PROTO_CLOUDFRONT, 30}, /* 44.234.90.252/30 */
    {0x2cea5b00u, PROTO_AWS, 24}, /* 44.234.91.0/24 */
    {0x2cea5c00u, PROTO_AWS, 22}, /* 44.234.92.0/22 */
    {0x2cea6000u, PROTO_AWS, 21}, /* 44.234.96.0/21 */
    {0x2cea6800u, PROTO_AWS, 22}, /* 44.234.104.0/22 */
    {0x2cea6c00u, PROTO_AWS, 25}, /* 44.234.108.0/25 */
    {0x2cea6c80u, PROTO_CLOUDFRONT, 25}, /* 44.234.108.128/25 */
    {0x2cea6d00u, PROTO_AWS, 24}, /* 44.234.109.0/24 */
    {0x2cea6e00u, PROTO_AWS, 23}, /* 44.234.110.0/23 */
    {0x2cea7000u, PROTO_AWS, 20}, /* 44.234.112.0/20 */
    {0x2cea8000u, PROTO_AWS, 17}, /* 44.234.128.0/17 */
    {0x2ceb0000u, PROTO_AWS, 16}, /* 44.235.0.0/16 */
    {0x2cec0000u, PROTO_AWS, 14}, /* 44.236.0.0/14 */
    {0x2cf00000u, PROTO_AWS, 12}, /* 44.240.0.0/12 */
    {0x2d000000u, PROTO_UNKNOWN, 0},
    {0x2d21a000u, PROTO_AWS, 22}, /* 45.33.160.0/22 */
    {0x2d21a400u, PROTO_UNKNOWN, 0},
    {0x2d21a500u, PROTO_AWS, 24}, /* 45.33.165.0/24 */
    {0x2d21a600u, PROTO_AWS, 23}, /* 45.33.166.0/23 */
    {0x2d21a800u, PROTO_AWS, 21}, /* 45.33.168.0/21 */
    {0x2d21b800u, PROTO_AWS, 22}, /* 45.33.184.0/22 */
    {0x2d21bc00u, PROTO_AWS, 24}, /* 45.33.188.0/24 */
    {0x2d21bd00u, PROTO_UNKNOWN, 0},
    {0x2d220000u, PROTO_AWS, 15}, /* 45.34.0.0/15 */
    {0x2d240000u, PROTO_UNKNOWN, 0},
    {0x2d390000u, PROTO_NETFLIX, 17}, /* 45.57.0.0/17 */
    {0x2d390800u, PROTO_NETFLIX, 23}, /* 45.57.8.0/23 */
    {0x2d390900u, PROTO_NETFLIX, 24}, /* 45.57.9.0/24 */
    {0x2d390a00u, PROTO_NETFLIX, 17}, /* 45.57.0.0/17 */
    {0x2d391000u, PROTO_NETFLIX, 24}, /* 45.57.16.0/24 */
    {0x2d391200u, PROTO_NETFLIX, 17}, /* 45.57.0.0/17 */
    {0x2d392800u, PROTO_NETFLIX, 24}, /* 45.57.40.0/24 */
    {0x2d392900u, PROTO_NETFLIX, 17}, /* 45.57.0.0/17 */
    {0x2d392a00u, PROTO_NETFLIX, 24}, /* 45.57.42.0/24 */
    {0x2d392b00u, PROTO_NETFLIX, 17}, /* 45.57.0.0/17 */
    {0x2d393400u, PROTO_NETFLIX, 24}, /* 45.57.52.0/24 */
    {0x2d393500u, PROTO_NETFLIX, 17}, /* 45.57.0.0/17 */
    {0x2d398000u, PROTO_AWS, 18}, /* 45.57.128.0/18 */
    {0x2d39c000u, PROTO_UNKNOWN, 0},
    {0x2d402800u, PROTO_FACEBOOK, 22}, /* 45.64.40.0/22 */
    {0x2d402c00u, PROTO_UNKNOWN, 0},
    {0x2d718000u, PROTO_AWS, 22}, /* 45.113.128.0/22 */
    {0x2d718400u, PROTO_UNKNOWN, 0},
    {0x2e338000u, PROTO_AWS, 18}, /* 46.51.128.0/18 */
    {0x2e33c000u, PROTO_AWS, 20}, /* 46.51.192.0/20 */
    {0x2e33d000u, PROTO_AWS, 22}, /* 46.51.208.0/22 */
    {0x2e33d400u, PROTO_UNKNOWN, 0},
    {0x2e33d800u, PROTO_AWS, 21}, /* 46.51.216.0/21 */
    {0x2e33e000u, PROTO_AWS, 19}, /* 46.51.224.0/19 */
    {0x2e340000u, PROTO_UNKNOWN, 0},
    {0x2e890000u, PROTO_AWS, 16}, /* 46.137.0.0/16 */
    {0x2e8a0000u, PROTO_UNKNOWN, 0},
    {0x2ea80000u, PROTO_AWS, 15}, /* 46.168.0.0/15 */
    {0x2eaa0000u, PROTO_UNKNOWN, 0},
    {0x2ee42000u, PROTO_YAHOO, 21}, /* 46.228.32.0/21 */
    {0x2ee43000u, PROTO_UNKNOWN, 0},
    {0x2f800000u, PROTO_AWS, 16}, /* 47.128.0.0/16 */
    {0x2f810000u, PROTO_AWS, 18}, /* 47.129.0.0/18 */
    {0x2f814000u, PROTO_AWS, 20}, /* 47.129.64.0/20 */
    {0x2f815000u, PROTO_AWS, 23}, /* 47.129.80.0/23 */
    {0x2f815200u, PROTO_CLOUDFRONT, 23}, /* 47.129.82.0/23 */
    {0x2f815400u, PROTO_CLOUDFRONT, 24}, /* 47.129.84.0/24 */
    {0x2f815500u, PROTO_AWS, 24}, /* 47.129.85.0/24 */
    {0x2f815600u, PROTO_AWS, 23}, /* 47.129.86.0/23 */
    {0x2f815800u, PROTO_AWS, 21}, /* 47.129.88.0/21 */
    {0x2f816000u, PROTO_AWS, 19}, /* 47.129.96.0/19 */
    {0x2f818000u, PROTO_AWS, 17}, /* 47.129.128.0/17 */
    {0x2f820000u, PROTO_AWS, 15}, /* 47.130.0.0/15 */
    {0x2f840000u, PROTO_UNKNOWN, 0},
    {0x30c00000u, PROTO_AZURE, 11}, /* 48.192.0.0/11 */
    {0x30e00000u, PROTO_UNKNOWN, 0},
    {0x32100000u, PROTO_AWS, 14}, /* 50.16.0.0/14 */
    {0x32140000u, PROTO_UNKNOWN, 0},
    {0x32550000u, PROTO_AZURE, 16}, /* 50.85.0.0/16 */
    {0x32560000u, PROTO_UNKNOWN, 0},
    {0x32700000u, PROTO_AWS, 16}, /* 50.112.0.0/16 */
    {0x32710000u, PROTO_UNKNOWN, 0},
    {0x33000000u, PROTO_AWS, 20}, /* 51.0.0.0/20 */
    {0x33001000u, PROTO_AWS, 21}, /* 51.0.16.0/21 */
    {0x33001800u, PROTO_AWS, 22}, /* 51.0.24.0/22 */
    {0x33001c00u, PROTO_AWS, 24}, /* 51.0.28.0/24 */
    {0x33001d00u, PROTO_AWS, 28}, /* 51.0.29.0/28 */
    {0x33001d10u, PROTO_UNKNOWN, 0},
    {0x33001d80u, PROTO_AWS, 28}, /* 51.0.29.128/28 */
    {0x33001d90u, PROTO_UNKNOWN, 0},
    {0x33001f00u, PROTO_AWS, 24}, /* 51.0.31.0/24 */
    {0x33002000u, PROTO_UNKNOWN, 0},
    {0x33004000u, PROTO_AWS, 18}, /* 51.0.64.0/18 */
    {0x33008000u, PROTO_AWS, 20}, /* 51.0.128.0/20 */
    {0x33009000u, PROTO_UNKNOWN, 0},
    {0x3300f900u, PROTO_AWS, 24}, /* 51.0.249.0/24 */
    {0x3300fa00u, PROTO_AWS, 30}, /* 51.0.250.0/30 */
    {0x3300fa04u, PROTO_UNKNOWN, 0},
    {0x3300fb00u, PROTO_AWS, 24}, /* 51.0.251.0/24 */
    {0x3300fd00u, PROTO_UNKNOWN, 0},
    {0x33040000u, PROTO_AZURE, 15}, /* 51.4.0.0/15 */
    {0x33060000u, PROTO_UNKNOWN, 0},
    {0x33080000u, PROTO_AZURE, 16}, /* 51.8.0.0/16 */
    {0x33090000u, PROTO_UNKNOWN, 0},
    {0x330b0000u, PROTO_AZURE, 16}, /* 51.11.0.0/16 */
    {0x330c0000u, PROTO_AZURE, 15}, /* 51.12.0.0/15 */
    {0x330e0000u, PROTO_UNKNOWN, 0},
    {0x33100000u, PROTO_AWS, 15}, /* 51.16.0.0/15 */
    {0x33120000u, PROTO_UNKNOWN, 0},
    {0x33140000u, PROTO_AWS, 15}, /* 51.20.0.0/15 */
    {0x33160000u, PROTO_UNKNOWN, 0},
    {0x33180000u, PROTO_AWS, 16}, /* 51.24.0.0/16 */
    {0x33190000u, PROTO_UNKNOWN, 0},
    {0x33220000u, PROTO_AWS, 15}, /* 51.34.0.0/15 */
    {0x33240000u, PROTO_UNKNOWN, 0},
    {0x332c0000u, PROTO_AWS, 17}, /* 51.44.0.0/17 */
    {0x332c8000u, PROTO_AWS, 18}, /* 51.44.128.0/18 */
    {0x332cc000u, PROTO_AWS, 19}, /* 51.44.192.0/19 */
    {0x332ce000u, PROTO_AWS, 21}, /* 51.44.224.0/21 */
    {0x332ce800u, PROTO_AWS, 23}, /* 51.44.232.0/23 */
    {0x332cea00u, PROTO_CLOUDFRONT, 23}, /* 51.44.234.0/23 */
    {0x332cec00u, PROTO_CLOUDFRONT, 22}, /* 51.44.236.0/22 */
    {0x332cf000u, PROTO_AWS, 20}, /* 51.44.240.0/20 */
    {0x332d0000u, PROTO_AWS, 16}, /* 51.45.0.0/16 */
    {0x332e0000u, PROTO_AWS, 15}, /* 51.46.0.0/15 */
    {0x33320000u, PROTO_UNKNOWN, 0},
    {0x33350000u, PROTO_AZURE, 16}, /* 51.53.0.0/16 */
    {0x33360000u, PROTO_UNKNOWN, 0},
    {0x33380000u, PROTO_AZURE, 14}, /* 51.56.0.0/14 */
    {0x333c0000u, PROTO_UNKNOWN, 0},
    {0x33480000u, PROTO_AWS, 19}, /* 51.72.0.0/19 */
    {0x33482000u, PROTO_AWS, 21}, /* 51.72.32.0/21 */
    {0x33482800u, PROTO_AWS, 25}, /* 51.72.40.0/25 */
    {0x33482880u, PROTO_CLOUDFRONT, 27}, /* 51.72.40.128/27 */
    {0x334828a0u, PROTO_AWS, 27}, /* 51.72.40.160/27 */
    {0x334828c0u, PROTO_AWS, 26}, /* 51.72.40.192/26 */
    {0x33482900u, PROTO_AWS, 24}, /* 51.72.41.0/24 */
    {0x33482a00u, PROTO_AWS, 23}, /* 51.72.42.0/23 */
    {0x33482c00u, PROTO_AWS, 22}, /* 51.72.44.0/22 */
    {0x33483000u, PROTO_AWS, 20}, /* 51.72.48.0/20 */
    {0x33484000u, PROTO_AWS, 18}, /* 51.72.64.0/18 */
    {0x33488000u, PROTO_AWS, 17}, /* 51.72.128.0/17 */
    {0x33490000u, PROTO_AWS, 16}, /* 51.73.0.0/16 */
    {0x334a0000u, PROTO_AWS, 20}, /* 51.74.0.0/20 */
    {0x334a1000u, PROTO_AWS, 23}, /* 51.74.16.0/23 */
    {0x334a1200u, PROTO_UNKNOWN, 0},
    {0x334a1400u, PROTO_CLOUDFRONT, 23}, /* 51.74.20.0/23 */
    {0x334a1600u, PROTO_CLOUDFRONT, 24}, /* 51.74.22.0/24 */
    {0x334a1700u, PROTO_UNKNOWN, 0},
    {0x334a4000u, PROTO_AWS, 18}, /* 51.74.64.0/18 */
    {0x334ac000u, PROTO_CLOUDFRONT, 18}, /* 51.74.192.0/18 */
    {0x334b0000u, PROTO_UNKNOWN, 0},
    {0x33540000u, PROTO_AWS, 14}, /* 51.84.0.0/14 */
    {0x33580000u, PROTO_UNKNOWN, 0},
    {0x335c0000u, PROTO_AWS, 14}, /* 51.92.0.0/14 */
    {0x33600000u, PROTO_AWS, 16}, /* 51.96.0.0/16 */
    {0x33610000u, PROTO_UNKNOWN, 0},
    {0x33640000u, PROTO_AWS, 15}, /* 51.100.0.0/15 */
    {0x33660000u, PROTO_AWS, 16}, /* 51.102.0.0/16 */
    {0x33670000u, PROTO_AZURE, 17}, /* 51.103.0.0/17 */
    {0x33678000u, PROTO_AZURE, 18}, /* 51.103.128.0/18 */
    {0x3367c000u, PROTO_AZURE, 26}, /* 51.103.192.0/26 */
    {0x3367c040u, PROTO_UNKNOWN, 0},
    {0x3367c800u, PROTO_AZURE, 21}, /* 51.103.200.0/21 */
    {0x3367d000u, PROTO_AZURE, 20}, /* 51.103.208.0/20 */
    {0x3367e000u, PROTO_AZURE, 19}, /* 51.103.224.0/19 */
    {0x33680000u, PROTO_AZURE, 15}, /* 51.104.0.0/15 */
    {0x336a0000u, PROTO_UNKNOWN, 0},
    {0x336b0000u, PROTO_AZURE, 16}, /* 51.107.0.0/16 */
    {0x336c0000u, PROTO_UNKNOWN, 0},
    {0x33700000u, PROTO_AWS, 16}, /* 51.112.0.0/16 */
    {0x33710000u, PROTO_UNKNOWN, 0},
    {0x33740000u, PROTO_AZURE, 16}, /* 51.116.0.0/16 */
    {0x33750000u, PROTO_UNKNOWN, 0},
    {0x33760000u, PROTO_AWS, 16}, /* 51.118.0.0/16 */
    {0x33770000u, PROTO_UNKNOWN, 0},
    {0x33780000u, PROTO_AZURE, 16}, /* 51.120.0.0/16 */
    {0x33790000u, PROTO_UNKNOWN, 0},
    {0x337c0000u, PROTO_AZURE, 16}, /* 51.124.0.0/16 */
    {0x337d0000u, PROTO_UNKNOWN, 0},
    {0x33840000u, PROTO_AZURE, 16}, /* 51.132.0.0/16 */
    {0x33850000u, PROTO_UNKNOWN, 0},
    {0x33880000u, PROTO_AZURE, 15}, /* 51.136.0.0/15 */
    {0x338a0000u, PROTO_AZURE, 17}, /* 51.138.0.0/17 */
    {0x338a8000u, PROTO_AZURE, 19}, /* 51.138.128.0/19 */
    {0x338aa000u, PROTO_AZURE, 21}, /* 51.138.160.0/21 */
    {0x338aa800u, PROTO_UNKNOWN, 0},
    {0x338ab000u, PROTO_AZURE, 20}, /* 51.138.176.0/20 */
    {0x338ac000u, PROTO_AZURE, 19}, /* 51.138.192.0/19 */
    {0x338ae000u, PROTO_AZURE, 20}, /* 51.138.224.0/20 */
    {0x338af000u, PROTO_UNKNOWN, 0},
    {0x338c0000u, PROTO_AZURE, 14}, /* 51.140.0.0/14 */
    {0x33900000u, PROTO_AZURE, 15}, /* 51.144.0.0/15 */
    {0x33920000u, PROTO_UNKNOWN, 0},
    {0x33a40000u, PROTO_AWS, 14}, /* 51.164.0.0/14 */
    {0x33a80000u, PROTO_AWS, 15}, /* 51.168.0.0/15 */
    {0x33aa0000u, PROTO_UNKNOWN, 0},
    {0x33ac0000u, PROTO_AWS, 15}, /* 51.172.0.0/15 */
    {0x33ae0000u, PROTO_UNKNOWN, 0},
    {0x33c80000u, PROTO_AWS, 13}, /* 51.200.0.0/13 */
    {0x33d00000u, PROTO_UNKNOWN, 0},
    {0x33e00000u, PROTO_AWS, 15}, /* 51.224.0.0/15 */
    {0x33e20000u, PROTO_UNKNOWN, 0},
    {0x34000000u, PROTO_AWS, 13}, /* 52.0.0.0/13 */
    {0x34080000u, PROTO_AWS, 14}, /* 52.8.0.0/14 */
    {0x340c0000u, PROTO_AWS, 15}, /* 52.12.0.0/15 */
    {0x340e0000u, PROTO_AWS, 16}, /* 52.14.0.0/16 */
    {0x340f0000u, PROTO_AWS, 18}, /* 52.15.0.0/18 */
    {0x340f4000u, PROTO_AWS, 19}, /* 52.15.64.0/19 */
    {0x340f6000u, PROTO_AWS, 20}, /* 52.15.96.0/20 */
    {0x340f7000u, PROTO_AWS, 21}, /* 52.15.112.0/21 */
    {0x340f7800u, PROTO_AWS, 22}, /* 52.15.120.0/22 */
    {0x340f7c00u, PROTO_AWS, 23}, /* 52.15.124.0/23 */
    {0x340f7e00u, PROTO_AWS, 24}, /* 52.15.126.0/24 */
    {0x340f7f00u, PROTO_AWS, 25}, /* 52.15.127.0/25 */
    {0x340f7f80u, PROTO_CLOUDFRONT, 26}, /* 52.15.127.128/26 */
    {0x340f7fc0u, PROTO_AWS, 26}, /* 52.15.127.192/26 */
    {0x340f8000u, PROTO_AWS, 17}, /* 52.15.128.0/17 */
    {0x34100000u, PROTO_AWS, 12}, /* 52.16.0.0/12 */
    {0x34200000u, PROTO_AWS, 13}, /* 52.32.0.0/13 */
    {0x34280000u, PROTO_AWS, 14}, /* 52.40.0.0/14 */
    {0x342c0000u, PROTO_AWS, 15}, /* 52.44.0.0/15 */
    {0x342e0000u, PROTO_CLOUDFRONT, 18}, /* 52.46.0.0/18 */
    {0x342e4000u, PROTO_AWS, 18}, /* 52.46.64.0/18 */
    {0x342e8000u, PROTO_AWS, 19}, /* 52.46.128.0/19 */
    {0x342ea000u, PROTO_UNKNOWN, 0},
    {0x342ea400u, PROTO_AWS, 22}, /* 52.46.164.0/22 */
    {0x342ea800u, PROTO_AWS, 21}, /* 52.46.168.0/21 */
    {0x342eb800u, PROTO_AWS, 22}, /* 52.46.184.0/22 */
    {0x342ebc00u, PROTO_UNKNOWN, 0},
    {0x342ec000u, PROTO_AWS, 19}, /* 52.46.192.0/19 */
    {0x342ee000u, PROTO_AWS, 20}, /* 52.46.224.0/20 */
    {0x342ef000u, PROTO_AWS, 22}, /* 52.46.240.0/22 */
    {0x342ef400u, PROTO_UNKNOWN, 0},
    {0x342ef900u, PROTO_AWS, 24}, /* 52.46.249.0/24 */
    {0x342efa00u, PROTO_AWS, 23}, /* 52.46.250.0/23 */
    {0x342efc00u, PROTO_AWS, 22}, /* 52.46.252.0/22 */
    {0x342f0000u, PROTO_AWS, 17}, /* 52.47.0.0/17 */
    {0x342f8000u, PROTO_AWS, 21}, /* 52.47.128.0/21 */
    {0x342f8800u, PROTO_AWS, 23}, /* 52.47.136.0/23 */
    {0x342f8a00u, PROTO_AWS, 24}, /* 52.47.138.0/24 */
    {0x342f8b00u, PROTO_CLOUDFRONT, 24}, /* 52.47.139.0/24 */
    {0x342f8c00u, PROTO_AWS, 22}, /* 52.47.140.0/22 */
    {0x342f9000u, PROTO_AWS, 20}, /* 52.47.144.0/20 */
    {0x342fa000u, PROTO_AWS, 19}, /* 52.47.160.0/19 */
    {0x342fc000u, PROTO_AWS, 18}, /* 52.47.192.0/18 */
    {0x34300000u, PROTO_AWS, 14}, /* 52.48.0.0/14 */
    {0x34340000u, PROTO_AWS, 17}, /* 52.52.0.0/17 */
    {0x34348000u, PROTO_AWS, 19}, /* 52.52.128.0/19 */
    {0x3434a000u, PROTO_AWS, 20}, /* 52.52.160.0/20 */
    {0x3434b000u, PROTO_AWS, 21}, /* 52.52.176.0/21 */
    {0x3434b800u, PROTO_AWS, 22}, /* 52.52.184.0/22 */
    {0x3434bc00u, PROTO_AWS, 23}, /* 52.52.188.0/23 */
    {0x3434be00u, PROTO_AWS, 24}, /* 52.52.190.0/24 */
    {0x3434bf00u, PROTO_AWS, 25}, /* 52.52.191.0/25 */
    {0x3434bf80u, PROTO_CLOUDFRONT, 26}, /* 52.52.191.128/26 */
    {0x3434bfc0u, PROTO_AWS, 26}, /* 52.52.191.192/26 */
    {0x3434c000u, PROTO_AWS, 18}, /* 52.52.192.0/18 */
    {0x34350000u, PROTO_AWS, 16}, /* 52.53.0.0/16 */
    {0x34360000u, PROTO_AWS, 15}, /* 52.54.0.0/15 */
    {0x34380000u, PROTO_AWS, 18}, /* 52.56.0.0/18 */
    {0x34384000u, PROTO_AWS, 19}, /* 52.56.64.0/19 */
    {0x34386000u, PROTO_AWS, 20}, /* 52.56.96.0/20 */
    {0x34387000u, PROTO_AWS, 21}, /* 52.56.112.0/21 */
    {0x34387800u, PROTO_AWS, 22}, /* 52.56.120.0/22 */
    {0x34387c00u, PROTO_AWS, 23}, /* 52.56.124.0/23 */
    {0x34387e00u, PROTO_AWS, 24}, /* 52.56.126.0/24 */
    {0x34387f00u, PROTO_CLOUDFRONT, 25}, /* 52.56.127.0/25 */
    {0x34387f80u, PROTO_AWS, 25}, /* 52.56.127.128/25 */
    {0x34388000u, PROTO_AWS, 17}, /* 52.56.128.0/17 */
    {0x34398000u, PROTO_AWS, 18}, /* 52.57.128.0/18 */
    {0x3439c000u, PROTO_AWS, 19}, /* 52.57.192.0/19 */
    {0x3439e000u, PROTO_AWS, 20}, /* 52.57.224.0/20 */
    {0x3439f000u, PROTO_AWS, 21}, /* 52.57.240.0/21 */
    {0x3439f800u, PROTO_AWS, 22}, /* 52.57.248.0/22 */
    {0x3439fc00u, PROTO_AWS, 23}, /* 52.57.252.0/23 */
    {0x3439fe00u, PROTO_CLOUDFRONT, 24}, /* 52.57.254.0/24 */
    {0x3439ff00u, PROTO_AWS, 24}, /* 52.57.255.0/24 */
    {0x343a0000u, PROTO_AWS, 15}, /* 52.58.0.0/15 */
    {0x343c0000u, PROTO_AWS, 14}, /* 52.60.0.0/14 */
    {0x34400000u, PROTO_AWS, 15}, /* 52.64.0.0/15 */
    {0x34420000u, PROTO_AWS, 17}, /* 52.66.0.0/17 */
    {0x34428000u, PROTO_AWS, 18}, /* 52.66.128.0/18 */
    {0x3442c000u, PROTO_AWS, 23}, /* 52.66.192.0/23 */
    {0x3442c200u, PROTO_AWS, 25}, /* 52.66.194.0/25 */
    {0x3442c280u, PROTO_CLOUDFRONT, 26}, /* 52.66.194.128/26 */
    {0x3442c2c0u, PROTO_AWS, 26}, /* 52.66.194.192/26 */
    {0x3442c300u, PROTO_AWS, 24}, /* 52.66.195.0/24 */
    {0x3442c400u, PROTO_AWS, 22}, /* 52.66.196.0/22 */
    {0x3442c800u, PROTO_AWS, 21}, /* 52.66.200.0/21 */
    {0x3442d000u, PROTO_AWS, 20}, /* 52.66.208.0/20 */
    {0x3442e000u, PROTO_AWS, 19}, /* 52.66.224.0/19 */
    {0x34430000u, PROTO_AWS, 16}, /* 52.67.0.0/16 */
    {0x34440000u, PROTO_AWS, 14}, /* 52.68.0.0/14 */
    {0x344c0000u, PROTO_AWS, 15}, /* 52.76.0.0/15 */
    {0x344e0000u, PROTO_AWS, 17}, /* 52.78.0.0/17 */
    {0x344e8000u, PROTO_AWS, 18}, /* 52.78.128.0/18 */
    {0x344ec000u, PROTO_AWS, 19}, /* 52.78.192.0/19 */
    {0x344ee000u, PROTO_AWS, 20}, /* 52.78.224.0/20 */
    {0x344ef000u, PROTO_AWS, 22}, /* 52.78.240.0/22 */
    {0x344ef400u, PROTO_AWS, 23}, /* 52.78.244.0/23 */
    {0x344ef600u, PROTO_AWS, 24}, /* 52.78.246.0/24 */
    {0x344ef700u, PROTO_AWS, 25}, /* 52.78.247.0/25 */
    {0x344ef780u, PROTO_CLOUDFRONT, 26}, /* 52.78.247.128/26 */
    {0x344ef7c0u, PROTO_AWS, 26}, /* 52.78.247.192/26 */
    {0x344ef800u, PROTO_AWS, 21}, /* 52.78.248.0/21 */
    {0x344f0000u, PROTO_AWS, 16}, /* 52.79.0.0/16 */
    {0x34500000u, PROTO_AWS, 15}, /* 52.80.0.0/15 */
    {0x34520000u, PROTO_AWS, 17}, /* 52.82.0.0/17 */
    {0x34528000u, PROTO_CLOUDFRONT, 19}, /* 52.82.128.0/19 */
    {0x3452a000u, PROTO_AWS, 21}, /* 52.82.160.0/21 */
    {0x3452a800u, PROTO_AWS, 24}, /* 52.82.168.0/24 */
    {0x3452a900u, PROTO_AWS, 27}, /* 52.82.169.0/27 */
    {0x3452a920u, PROTO_UNKNOWN, 0},
    {0x3452aa00u, PROTO_AWS, 23}, /* 52.82.170.0/23 */
    {0x3452ac00u, PROTO_UNKNOWN, 0},
    {0x3452b000u, PROTO_AWS, 21}, /* 52.82.176.0/21 */
    {0x3452b800u, PROTO_AWS, 23}, /* 52.82.184.0/23 */
    {0x3452ba00u, PROTO_UNKNOWN, 0},
    {0x3452bb00u, PROTO_AWS, 24}, /* 52.82.187.0/24 */
    {0x3452bc00u, PROTO_AWS, 22}, /* 52.82.188.0/22 */
    {0x3452c000u, PROTO_AWS, 18}, /* 52.82.192.0/18 */
    {0x34530000u, PROTO_AWS, 16}, /* 52.83.0.0/16 */
    {0x34540000u, PROTO_CLOUDFRONT, 15}, /* 52.84.0.0/15 */
    {0x34560000u, PROTO_AWS, 15}, /* 52.86.0.0/15 */
    {0x34580000u, PROTO_AWS, 14}, /* 52.88.0.0/14 */
    {0x345c0000u, PROTO_AWS, 16}, /* 52.92.0.0/16 */
    {0x345d0000u, PROTO_AWS, 21}, /* 52.93.0.0/21 */
    {0x345d0800u, PROTO_AWS, 22}, /* 52.93.8.0/22 */
    {0x345d0c00u, PROTO_AWS, 24}, /* 52.93.12.0/24 */
    {0x345d0d00u, PROTO_UNKNOWN, 0},
    {0x345d0e00u, PROTO_AWS, 24}, /* 52.93.14.0/24 */
    {0x345d0f00u, PROTO_UNKNOWN, 0},
    {0x345d1000u, PROTO_AWS, 22}, /* 52.93.16.0/22 */
    {0x345d1400u, PROTO_AWS, 23}, /* 52.93.20.0/23 */
    {0x345d1600u, PROTO_UNKNOWN, 0},
    {0x345d1630u, PROTO_AWS, 28}, /* 52.93.22.48/28 */
    {0x345d1640u, PROTO_AWS, 29}, /* 52.93.22.64/29 */
    {0x345d1648u, PROTO_UNKNOWN, 0},
    {0x345d1700u, PROTO_AWS, 24}, /* 52.93.23.0/24 */
    {0x345d1800u, PROTO_AWS, 21}, /* 52.93.24.0/21 */
    {0x345d2000u, PROTO_UNKNOWN, 0},
    {0x345d20b0u, PROTO_AWS, 32}, /* 52.93.32.176/32 */
    {0x345d20b1u, PROTO_UNKNOWN, 0},
    {0x345d20b3u, PROTO_AWS, 32}, /* 52.93.32.179/32 */
    {0x345d20b5u, PROTO_UNKNOWN, 0},
    {0x345d20b7u, PROTO_AWS, 32}, /* 52.93.32.183/32 */
    {0x345d20b9u, PROTO_UNKNOWN, 0},
    {0x345d2108u, PROTO_AWS, 30}, /* 52.93.33.8/30 */
    {0x345d210cu, PROTO_UNKNOWN, 0},
    {0x345d21e0u, PROTO_AWS, 31}, /* 52.93.33.224/31 */
    {0x345d21e2u, PROTO_UNKNOWN, 0},
    {0x345d21e6u, PROTO_AWS, 31}, /* 52.93.33.230/31 */
    {0x345d21e8u, PROTO_UNKNOWN, 0},
    {0x345d2200u, PROTO_AWS, 23}, /* 52.93.34.0/23 */
    {0x345d2400u, PROTO_AWS, 22}, /* 52.93.36.0/22 */
    {0x345d2c00u, PROTO_AWS, 23}, /* 52.93.44.0/23 */
    {0x345d2e00u, PROTO_UNKNOWN, 0},
    {0x345d2f00u, PROTO_AWS, 24}, /* 52.93.47.0/24 */
    {0x345d3000u, PROTO_AWS, 22}, /* 52.93.48.0/22 */
    {0x345d3400u, PROTO_UNKNOWN, 0},
    {0x345d34a0u, PROTO_AWS, 29}, /* 52.93.52.160/29 */
    {0x345d34a8u, PROTO_UNKNOWN, 0},
    {0x345d3500u, PROTO_AWS, 29}, /* 52.93.53.0/29 */
    {0x345d3508u, PROTO_UNKNOWN, 0},
    {0x345d3790u, PROTO_AWS, 30}, /* 52.93.55.144/30 */
    {0x345d3794u, PROTO_AWS, 31}, /* 52.93.55.148/31 */
    {0x345d3796u, PROTO_UNKNOWN, 0},
    {0x345d3798u, PROTO_AWS, 29}, /* 52.93.55.152/29 */
    {0x345d37a8u, PROTO_UNKNOWN, 0},
    {0x345d3800u, PROTO_AWS, 21}, /* 52.93.56.0/21 */
    {0x345d4000u, PROTO_AWS, 22}, /* 52.93.64.0/22 */
    {0x345d4400u, PROTO_AWS, 23}, /* 52.93.68.0/23 */
    {0x345d4600u, PROTO_UNKNOWN, 0},
    {0x345d4628u, PROTO_AWS, 29}, /* 52.93.70.40/29 */
    {0x345d4630u, PROTO_UNKNOWN, 0},
    {0x345d4680u, PROTO_AWS, 25}, /* 52.93.70.128/25 */
    {0x345d4700u, PROTO_UNKNOWN, 0},
    {0x345d4725u, PROTO_AWS, 32}, /* 52.93.71.37/32 */
    {0x345d4726u, PROTO_AWS, 31}, /* 52.93.71.38/31 */
    {0x345d4728u, PROTO_AWS, 29}, /* 52.93.71.40/29 */
    {0x345d4730u, PROTO_UNKNOWN, 0},
    {0x345d4800u, PROTO_AWS, 21}, /* 52.93.72.0/21 */
    {0x345d5000u, PROTO_AWS, 22}, /* 52.93.80.0/22 */
    {0x345d5400u, PROTO_UNKNOWN, 0},
    {0x345d54a0u, PROTO_AWS, 29}, /* 52.93.84.160/29 */
    {0x345d54a8u, PROTO_UNKNOWN, 0},
    {0x345d54c0u, PROTO_AWS, 29}, /* 52.93.84.192/29 */
    {0x345d54c8u, PROTO_UNKNOWN, 0},
    {0x345d56a0u, PROTO_AWS, 29}, /* 52.93.86.160/29 */
    {0x345d56a8u, PROTO_UNKNOWN, 0},
    {0x345d56c0u, PROTO_AWS, 29}, /* 52.93.86.192/29 */
    {0x345d56c8u, PROTO_UNKNOWN, 0},
    {0x345d5760u, PROTO_AWS, 27}, /* 52.93.87.96/27 */
    {0x345d5780u, PROTO_UNKNOWN, 0},
    {0x345d58a0u, PROTO_AWS, 29}, /* 52.93.88.160/29 */
    {0x345d58a8u, PROTO_UNKNOWN, 0},
    {0x345d58c0u, PROTO_AWS, 29}, /* 52.93.88.192/29 */
    {0x345d58c8u, PROTO_UNKNOWN, 0},
    {0x345d5aa0u, PROTO_AWS, 29}, /* 52.93.90.160/29 */
    {0x345d5aa8u, PROTO_UNKNOWN, 0},
    {0x345d5ac0u, PROTO_AWS, 29}, /* 52.93.90.192/29 */
    {0x345d5ac8u, PROTO_UNKNOWN, 0},
    {0x345d5b60u, PROTO_AWS, 28}, /* 52.93.91.96/28 */
    {0x345d5b70u, PROTO_AWS, 30}, /* 52.93.91.112/30 */
    {0x345d5b74u, PROTO_UNKNOWN, 0},
    {0x345d5c00u, PROTO_AWS, 22}, /* 52.93.92.0/22 */
    {0x345d6400u, PROTO_AWS, 23}, /* 52.93.100.0/23 */
    {0x345d6600u, PROTO_UNKNOWN, 0},
    {0x345d6f00u, PROTO_AWS, 24}, /* 52.93.111.0/24 */
    {0x345d7000u, PROTO_AWS, 23}, /* 52.93.112.0/23 */
    {0x345d7200u, PROTO_UNKNOWN, 0},
    {0x345d7300u, PROTO_AWS, 24}, /* 52.93.115.0/24 */
    {0x345d7500u, PROTO_UNKNOWN, 0},
    {0x345d7790u, PROTO_AWS, 30}, /* 52.93.119.144/30 */
    {0x345d7794u, PROTO_UNKNOWN, 0},
    {0x345d78b0u, PROTO_AWS, 30}, /* 52.93.120.176/30 */
    {0x345d78b4u, PROTO_UNKNOWN, 0},
    {0x345d79bbu, PROTO_AWS, 32}, /* 52.93.121.187/32 */
    {0x345d79bcu, PROTO_AWS, 31}, /* 52.93.121.188/31 */
    {0x345d79beu, PROTO_AWS, 32}, /* 52.93.121.190/32 */
    {0x345d79bfu, PROTO_UNKNOWN, 0},
    {0x345d79c3u, PROTO_AWS, 32}, /* 52.93.121.195/32 */
    {0x345d79c4u, PROTO_AWS, 31}, /* 52.93.121.196/31 */
    {0x345d79c6u, PROTO_AWS, 32}, /* 52.93.121.198/32 */
    {0x345d79c7u, PROTO_UNKNOWN, 0},
    {0x345d7a83u, PROTO_AWS, 32}, /* 52.93.122.131/32 */
    {0x345d7a84u, PROTO_UNKNOWN, 0},
    {0x345d7acau, PROTO_AWS, 31}, /* 52.93.122.202/31 */
    {0x345d7accu, PROTO_UNKNOWN, 0},
    {0x345d7adau, PROTO_AWS, 32}, /* 52.93.122.218/32 */
    {0x345d7adbu, PROTO_UNKNOWN, 0},
    {0x345d7affu, PROTO_AWS, 32}, /* 52.93.122.255/32 */
    {0x345d7b00u, PROTO_UNKNOWN, 0},
    {0x345d7b06u, PROTO_AWS, 32}, /* 52.93.123.6/32 */
    {0x345d7b07u, PROTO_UNKNOWN, 0},
    {0x345d7b0bu, PROTO_AWS, 32}, /* 52.93.123.11/32 */
    {0x345d7b0cu, PROTO_UNKNOWN, 0},
    {0x345d7b62u, PROTO_AWS, 31}, /* 52.93.123.98/31 */
    {0x345d7b64u, PROTO_UNKNOWN, 0},
    {0x345d7b88u, PROTO_AWS, 32}, /* 52.93.123.136/32 */
    {0x345d7b89u, PROTO_UNKNOWN, 0},
    {0x345d7bffu, PROTO_AWS, 32}, /* 52.93.123.255/32 */
    {0x345d7c00u, PROTO_UNKNOWN, 0},
    {0x345d7c0eu, PROTO_AWS, 31}, /* 52.93.124.14/31 */
    {0x345d7c10u, PROTO_UNKNOWN, 0},
    {0x345d7c60u, PROTO_AWS, 31}, /* 52.93.124.96/31 */
    {0x345d7c62u, PROTO_UNKNOWN, 0},
    {0x345d7cd2u, PROTO_AWS, 31}, /* 52.93.124.210/31 */
    {0x345d7cd6u, PROTO_UNKNOWN, 0},
    {0x345d7d2au, PROTO_AWS, 31}, /* 52.93.125.42/31 */
    {0x345d7d2cu, PROTO_UNKNOWN, 0},
    {0x345d7e4cu, PROTO_AWS, 32}, /* 52.93.126.76/32 */
    {0x345d7e4du, PROTO_UNKNOWN, 0},
    {0x345d7e7au, PROTO_AWS, 31}, /* 52.93.126.122/31 */
    {0x345d7e7cu, PROTO_UNKNOWN, 0},
    {0x345d7e82u, PROTO_AWS, 31}, /* 52.93.126.130/31 */
    {0x345d7e84u, PROTO_AWS, 30}, /* 52.93.126.132/30 */
    {0x345d7e8cu, PROTO_UNKNOWN, 0},
    {0x345d7e90u, PROTO_AWS, 30}, /* 52.93.126.144/30 */
    {0x345d7e94u, PROTO_UNKNOWN, 0},
    {0x345d7ec6u, PROTO_AWS, 31}, /* 52.93.126.198/31 */
    {0x345d7ec8u, PROTO_UNKNOWN, 0},
    {0x345d7eccu, PROTO_AWS, 30}, /* 52.93.126.204/30 */
    {0x345d7ed0u, PROTO_UNKNOWN, 0},
    {0x345d7ed4u, PROTO_AWS, 30}, /* 52.93.126.212/30 */
    {0x345d7ed8u, PROTO_UNKNOWN, 0},
    {0x345d7eeau, PROTO_AWS, 31}, /* 52.93.126.234/31 */
    {0x345d7eecu, PROTO_UNKNOWN, 0},
    {0x345d7ef4u, PROTO_AWS, 31}, /* 52.93.126.244/31 */
    {0x345d7ef6u, PROTO_UNKNOWN, 0},
    {0x345d7efau, PROTO_AWS, 31}, /* 52.93.126.250/31 */
    {0x345d7efcu, PROTO_UNKNOWN, 0},
    {0x345d7f11u, PROTO_AWS, 32}, /* 52.93.127.17/32 */
    {0x345d7f12u, PROTO_AWS, 31}, /* 52.93.127.18/31 */
    {0x345d7f14u, PROTO_UNKNOWN, 0},
    {0x345d7f18u, PROTO_AWS, 30}, /* 52.93.127.24/30 */
    {0x345d7f1cu, PROTO_UNKNOWN, 0},
    {0x345d7f44u, PROTO_AWS, 30}, /* 52.93.127.68/30 */
    {0x345d7f48u, PROTO_UNKNOWN, 0},
    {0x345d7f5cu, PROTO_AWS, 30}, /* 52.93.127.92/30 */
    {0x345d7f60u, PROTO_AWS, 27}, /* 52.93.127.96/27 */
    {0x345d7f80u, PROTO_AWS, 30}, /* 52.93.127.128/30 */
    {0x345d7f84u, PROTO_AWS, 31}, /* 52.93.127.132/31 */
    {0x345d7f86u, PROTO_UNKNOWN, 0},
    {0x345d7f8au, PROTO_AWS, 31}, /* 52.93.127.138/31 */
    {0x345d7f8cu, PROTO_UNKNOWN, 0},
    {0x345d7f92u, PROTO_AWS, 31}, /* 52.93.127.146/31 */
    {0x345d7f96u, PROTO_UNKNOWN, 0},
    {0x345d7f98u, PROTO_AWS, 29}, /* 52.93.127.152/29 */
    {0x345d7fa8u, PROTO_AWS, 31}, /* 52.93.127.168/31 */
    {0x345d7faau, PROTO_UNKNOWN, 0},
    {0x345d7facu, PROTO_AWS, 30}, /* 52.93.127.172/30 */
    {0x345d7fb0u, PROTO_AWS, 29}, /* 52.93.127.176/29 */
    {0x345d7fb8u, PROTO_AWS, 31}, /* 52.93.127.184/31 */
    {0x345d7fbau, PROTO_UNKNOWN, 0},
    {0x345d7fc2u, PROTO_AWS, 31}, /* 52.93.127.194/31 */
    {0x345d7fc4u, PROTO_AWS, 30}, /* 52.93.127.196/30 */
    {0x345d7fc8u, PROTO_AWS, 29}, /* 52.93.127.200/29 */
    {0x345d7fd0u, PROTO_UNKNOWN, 0},
    {0x345d7fd8u, PROTO_AWS, 30}, /* 52.93.127.216/30 */
    {0x345d7fdcu, PROTO_AWS, 31}, /* 52.93.127.220/31 */
    {0x345d7fdeu, PROTO_UNKNOWN, 0},
    {0x345d7fe8u, PROTO_AWS, 32}, /* 52.93.127.232/32 */
    {0x345d7fe9u, PROTO_UNKNOWN, 0},
    {0x345d7fedu, PROTO_AWS, 32}, /* 52.93.127.237/32 */
    {0x345d7feeu, PROTO_AWS, 31}, /* 52.93.127.238/31 */
    {0x345d7ff0u, PROTO_UNKNOWN, 0},
    {0x345d7ff4u, PROTO_AWS, 30}, /* 52.93.127.244/30 */
    {0x345d7ff8u, PROTO_AWS, 29}, /* 52.93.127.248/29 */
    {0x345d8000u, PROTO_UNKNOWN, 0},
    {0x345d815fu, PROTO_AWS, 32}, /* 52.93.129.95/32 */
    {0x345d8160u, PROTO_UNKNOWN, 0},
    {0x345d83d9u, PROTO_AWS, 32}, /* 52.93.131.217/32 */
    {0x345d83dau, PROTO_UNKNOWN, 0},
    {0x345d857fu, PROTO_AWS, 32}, /* 52.93.133.127/32 */
    {0x345d8580u, PROTO_UNKNOWN, 0},
    {0x345d8581u, PROTO_AWS, 32}, /* 52.93.133.129/32 */
    {0x345d8582u, PROTO_UNKNOWN, 0},
    {0x345d8583u, PROTO_AWS, 32}, /* 52.93.133.131/32 */
    {0x345d8584u, PROTO_UNKNOWN, 0},
    {0x345d8585u, PROTO_AWS, 32}, /* 52.93.133.133/32 */
    {0x345d8586u, PROTO_UNKNOWN, 0},
    {0x345d8599u, PROTO_AWS, 32}, /* 52.93.133.153/32 */
    {0x345d859au, PROTO_UNKNOWN, 0},
    {0x345d859bu, PROTO_AWS, 32}, /* 52.93.133.155/32 */
    {0x345d859cu, PROTO_UNKNOWN, 0},
    {0x345d85afu, PROTO_AWS, 32}, /* 52.93.133.175/32 */
    {0x345d85b0u, PROTO_UNKNOWN, 0},
    {0x345d85b1u, PROTO_AWS, 32}, /* 52.93.133.177/32 */
    {0x345d85b2u, PROTO_UNKNOWN, 0},
    {0x345d85b3u, PROTO_AWS, 32}, /* 52.93.133.179/32 */
    {0x345d85b4u, PROTO_UNKNOWN, 0},
    {0x345d85b5u, PROTO_AWS, 32}, /* 52.93.133.181/32 */
    {0x345d85b6u, PROTO_UNKNOWN, 0},
    {0x345d86b5u, PROTO_AWS, 32}, /* 52.93.134.181/32 */
    {0x345d86b6u, PROTO_UNKNOWN, 0},
    {0x345d87c3u, PROTO_AWS, 32}, /* 52.93.135.195/32 */
    {0x345d87c4u, PROTO_UNKNOWN, 0},
    {0x345d8800u, PROTO_AWS, 22}, /* 52.93.136.0/22 */
    {0x345d8c00u, PROTO_AWS, 24}, /* 52.93.140.0/24 */
    {0x345d8d00u, PROTO_UNKNOWN, 0},
    {0x345d8d80u, PROTO_AWS, 25}, /* 52.93.141.128/25 */
    {0x345d8e00u, PROTO_UNKNOWN, 0},
    {0x345d9200u, PROTO_AWS, 23}, /* 52.93.146.0/23 */
    {0x345d9400u, PROTO_AWS, 25}, /* 52.93.148.0/25 */
    {0x345d9480u, PROTO_AWS, 26}, /* 52.93.148.128/26 */
    {0x345d94c0u, PROTO_UNKNOWN, 0},
    {0x345d9500u, PROTO_AWS, 24}, /* 52.93.149.0/24 */
    {0x345d9600u, PROTO_AWS, 23}, /* 52.93.150.0/23 */
    {0x345d9800u, PROTO_UNKNOWN, 0},
    {0x345d98a0u, PROTO_AWS, 29}, /* 52.93.152.160/29 */
    {0x345d98a8u, PROTO_UNKNOWN, 0},
    {0x345d98c0u, PROTO_AWS, 29}, /* 52.93.152.192/29 */
    {0x345d98c8u, PROTO_UNKNOWN, 0},
    {0x345d9940u, PROTO_AWS, 29}, /* 52.93.153.64/29 */
    {0x345d9948u, PROTO_UNKNOWN, 0},
    {0x345d9950u, PROTO_AWS, 32}, /* 52.93.153.80/32 */
    {0x345d9951u, PROTO_UNKNOWN, 0},
    {0x345d9960u, PROTO_AWS, 29}, /* 52.93.153.96/29 */
    {0x345d9968u, PROTO_UNKNOWN, 0},
    {0x345d9980u, PROTO_AWS, 29}, /* 52.93.153.128/29 */
    {0x345d9988u, PROTO_UNKNOWN, 0},
    {0x345d9994u, PROTO_AWS, 31}, /* 52.93.153.148/31 */
    {0x345d9996u, PROTO_UNKNOWN, 0},
    {0x345d99a8u, PROTO_AWS, 29}, /* 52.93.153.168/29 */
    {0x345d99b0u, PROTO_AWS, 30}, /* 52.93.153.176/30 */
    {0x345d99b4u, PROTO_UNKNOWN, 0},
    {0x345d9c00u, PROTO_AWS, 22}, /* 52.93.156.0/22 */
    {0x345da000u, PROTO_UNKNOWN, 0},
    {0x345db280u, PROTO_AWS, 26}, /* 52.93.178.128/26 */
    {0x345db2c0u, PROTO_AWS, 27}, /* 52.93.178.192/27 */
    {0x345db2e0u, PROTO_AWS, 29}, /* 52.93.178.224/29 */
    {0x345db2e8u, PROTO_AWS, 30}, /* 52.93.178.232/30 */
    {0x345db2ecu, PROTO_UNKNOWN, 0},
    {0x345db680u, PROTO_AWS, 26}, /* 52.93.182.128/26 */
    {0x345db6c0u, PROTO_UNKNOWN, 0},
    {0x345db740u, PROTO_AWS, 27}, /* 52.93.183.64/27 */
    {0x345db760u, PROTO_UNKNOWN, 0},
    {0x345dc1c0u, PROTO_AWS, 29}, /* 52.93.193.192/29 */
    {0x345dc1c8u, PROTO_AWS, 30}, /* 52.93.193.200/30 */
    {0x345dc1ccu, PROTO_UNKNOWN, 0},
    {0x345dc600u, PROTO_AWS, 25}, /* 52.93.198.0/25 */
    {0x345dc680u, PROTO_UNKNOWN, 0},
    {0x345dc718u, PROTO_AWS, 29}, /* 52.93.199.24/29 */
    {0x345dc720u, PROTO_AWS, 28}, /* 52.93.199.32/28 */
    {0x345dc730u, PROTO_UNKNOWN, 0},
    {0x345dc758u, PROTO_AWS, 29}, /* 52.93.199.88/29 */
    {0x345dc760u, PROTO_AWS, 28}, /* 52.93.199.96/28 */
    {0x345dc770u, PROTO_UNKNOWN, 0},
    {0x345dc950u, PROTO_AWS, 28}, /* 52.93.201.80/28 */
    {0x345dc970u, PROTO_UNKNOWN, 0},
    {0x345de4a0u, PROTO_AWS, 29}, /* 52.93.228.160/29 */
    {0x345de4a8u, PROTO_UNKNOWN, 0},
    {0x345de4c0u, PROTO_AWS, 29}, /* 52.93.228.192/29 */
    {0x345de4c8u, PROTO_UNKNOWN, 0},
    {0x345de540u, PROTO_AWS, 29}, /* 52.93.229.64/29 */
    {0x345de548u, PROTO_UNKNOWN, 0},
    {0x345de560u, PROTO_AWS, 29}, /* 52.93.229.96/29 */
    {0x345de568u, PROTO_UNKNOWN, 0},
    {0x345de580u, PROTO_AWS, 29}, /* 52.93.229.128/29 */
    {0x345de588u, PROTO_UNKNOWN, 0},
    {0x345de594u, PROTO_AWS, 31}, /* 52.93.229.148/31 */
    {0x345de596u, PROTO_UNKNOWN, 0},
    {0x345dec00u, PROTO_AWS, 22}, /* 52.93.236.0/22 */
    {0x345df400u, PROTO_AWS, 23}, /* 52.93.244.0/23 */
    {0x345df600u, PROTO_UNKNOWN, 0},
    {0x345df6d8u, PROTO_AWS, 29}, /* 52.93.246.216/29 */
    {0x345df6e0u, PROTO_UNKNOWN, 0},
    {0x345df700u, PROTO_AWS, 25}, /* 52.93.247.0/25 */
    {0x345df780u, PROTO_UNKNOWN, 0},
    {0x345df800u, PROTO_AWS, 22}, /* 52.93.248.0/22 */
    {0x345dfc00u, PROTO_UNKNOWN, 0},
    {0x345dfe00u, PROTO_AWS, 23}, /* 52.93.254.0/23 */
    {0x345e0000u, PROTO_AWS, 20}, /* 52.94.0.0/20 */
    {0x345e1000u, PROTO_AWS, 22}, /* 52.94.16.0/22 */
    {0x345e1400u, PROTO_AWS, 24}, /* 52.94.20.0/24 */
    {0x345e1500u, PROTO_UNKNOWN, 0},
    {0x345e1600u, PROTO_AWS, 23}, /* 52.94.22.0/23 */
    {0x345e1800u, PROTO_AWS, 22}, /* 52.94.24.0/22 */
    {0x345e1c00u, PROTO_AWS, 23}, /* 52.94.28.0/23 */
    {0x345e1e00u, PROTO_AWS, 24}, /* 52.94.30.0/24 */
    {0x345e1f00u, PROTO_UNKNOWN, 0},
    {0x345e2000u, PROTO_AWS, 19}, /* 52.94.32.0/19 */
    {0x345e4000u, PROTO_AWS, 22}, /* 52.94.64.0/22 */
    {0x345e4400u, PROTO_AWS, 23}, /* 52.94.68.0/23 */
    {0x345e4600u, PROTO_UNKNOWN, 0},
    {0x345e4800u, PROTO_AWS, 21}, /* 52.94.72.0/21 */
    {0x345e5000u, PROTO_AWS, 20}, /* 52.94.80.0/20 */
    {0x345e6000u, PROTO_AWS, 19}, /* 52.94.96.0/19 */
    {0x345e8000u, PROTO_AWS, 20}, /* 52.94.128.0/20 */
    {0x345e9000u, PROTO_AWS, 23}, /* 52.94.144.0/23 */
    {0x345e9200u, PROTO_AWS, 24}, /* 52.94.146.0/24 */
    {0x345e9300u, PROTO_UNKNOWN, 0},
    {0x345e9400u, PROTO_AWS, 22}, /* 52.94.148.0/22 */
    {0x345e9800u, PROTO_UNKNOWN, 0},
    {0x345e9803u, PROTO_AWS, 32}, /* 52.94.152.3/32 */
    {0x345e9804u, PROTO_UNKNOWN, 0},
    {0x345e9809u, PROTO_AWS, 32}, /* 52.94.152.9/32 */
    {0x345e980au, PROTO_UNKNOWN, 0},
    {0x345e980bu, PROTO_AWS, 32}, /* 52.94.152.11/32 */
    {0x345e980du, PROTO_UNKNOWN, 0},
    {0x345e982cu, PROTO_AWS, 32}, /* 52.94.152.44/32 */
    {0x345e982du, PROTO_UNKNOWN, 0},
    {0x345e983cu, PROTO_AWS, 30}, /* 52.94.152.60/30 */
    {0x345e9844u, PROTO_AWS, 31}, /* 52.94.152.68/31 */
    {0x345e9846u, PROTO_UNKNOWN, 0},
    {0x345e98b0u, PROTO_AWS, 28}, /* 52.94.152.176/28 */
    {0x345e98c0u, PROTO_AWS, 30}, /* 52.94.152.192/30 */
    {0x345e98c4u, PROTO_UNKNOWN, 0},
    {0x345ea000u, PROTO_AWS, 19}, /* 52.94.160.0/19 */
    {0x345ec000u, PROTO_AWS, 22}, /* 52.94.192.0/22 */
    {0x345ec400u, PROTO_AWS, 23}, /* 52.94.196.0/23 */
    {0x345ec600u, PROTO_AWS, 25}, /* 52.94.198.0/25 */
    {0x345ec680u, PROTO_AWS, 27}, /* 52.94.198.128/27 */
    {0x345ec6a0u, PROTO_UNKNOWN, 0},
    {0x345ec700u, PROTO_AWS, 24}, /* 52.94.199.0/24 */
    {0x345ec900u, PROTO_AWS, 25}, /* 52.94.201.0/25 */
    {0x345ec980u, PROTO_UNKNOWN, 0},
    {0x345ecc00u, PROTO_AWS, 22}, /* 52.94.204.0/22 */
    {0x345ed000u, PROTO_AWS, 20}, /* 52.94.208.0/20 */
    {0x345ef000u, PROTO_AWS, 21}, /* 52.94.240.0/21 */
    {0x345ef800u, PROTO_AWS, 25}, /* 52.94.248.0/25 */
    {0x345ef880u, PROTO_AWS, 26}, /* 52.94.248.128/26 */
    {0x345ef8c0u, PROTO_AWS, 27}, /* 52.94.248.192/27 */
    {0x345ef8e0u, PROTO_AWS, 28}, /* 52.94.248.224/28 */
    {0x345ef8f0u, PROTO_UNKNOWN, 0},
    {0x345ef920u, PROTO_AWS, 27}, /* 52.94.249.32/27 */
    {0x345ef940u, PROTO_AWS, 26}, /* 52.94.249.64/26 */
    {0x345ef980u, PROTO_AWS, 25}, /* 52.94.249.128/25 */
    {0x345efa00u, PROTO_AWS, 26}, /* 52.94.250.0/26 */
    {0x345efa40u, PROTO_UNKNOWN, 0},
    {0x345efa50u, PROTO_AWS, 28}, /* 52.94.250.80/28 */
    {0x345efa60u, PROTO_AWS, 27}, /* 52.94.250.96/27 */
    {0x345efa80u, PROTO_AWS, 26}, /* 52.94.250.128/26 */
    {0x345efac0u, PROTO_AWS, 28}, /* 52.94.250.192/28 */
    {0x345efad0u, PROTO_UNKNOWN, 0},
    {0x345efc00u, PROTO_AWS, 22}, /* 52.94.252.0/22 */
    {0x345f0000u, PROTO_AWS, 20}, /* 52.95.0.0/20 */
    {0x345f1000u, PROTO_AWS, 21}, /* 52.95.16.0/21 */
    {0x345f1800u, PROTO_AWS, 22}, /* 52.95.24.0/22 */
    {0x345f1c00u, PROTO_AWS, 24}, /* 52.95.28.0/24 */
    {0x345f1d00u, PROTO_AWS, 26}, /* 52.95.29.0/26 */
    {0x345f1d40u, PROTO_UNKNOWN, 0},
    {0x345f1e00u, PROTO_AWS, 23}, /* 52.95.30.0/23 */
    {0x345f2000u, PROTO_UNKNOWN, 0},
    {0x345f2200u, PROTO_AWS, 23}, /* 52.95.34.0/23 */
    {0x345f2400u, PROTO_AWS, 22}, /* 52.95.36.0/22 */
    {0x345f2800u, PROTO_AWS, 23}, /* 52.95.40.0/23 */
    {0x345f2a00u, PROTO_AWS, 24}, /* 52.95.42.0/24 */
    {0x345f2b00u, PROTO_UNKNOWN, 0},
    {0x345f3000u, PROTO_AWS, 20}, /* 52.95.48.0/20 */
    {0x345f4000u, PROTO_AWS, 18}, /* 52.95.64.0/18 */
    {0x345fc000u, PROTO_AWS, 20}, /* 52.95.192.0/20 */
    {0x345fd000u, PROTO_AWS, 21}, /* 52.95.208.0/21 */
    {0x345fd800u, PROTO_AWS, 22}, /* 52.95.216.0/22 */
    {0x345fdc00u, PROTO_UNKNOWN, 0},
    {0x345fe000u, PROTO_AWS, 22}, /* 52.95.224.0/22 */
    {0x345fe400u, PROTO_AWS, 23}, /* 52.95.228.0/23 */
    {0x345fe600u, PROTO_AWS, 24}, /* 52.95.230.0/24 */
    {0x345fe700u, PROTO_UNKNOWN, 0},
    {0x345feb00u, PROTO_AWS, 24}, /* 52.95.235.0/24 */
    {0x345fec00u, PROTO_UNKNOWN, 0},
    {0x345fef00u, PROTO_AWS, 24}, /* 52.95.239.0/24 */
    {0x345ff000u, PROTO_AWS, 21}, /* 52.95.240.0/21 */
    {0x345ff800u, PROTO_AWS, 22}, /* 52.95.248.0/22 */
    {0x345ffc00u, PROTO_AWS, 23}, /* 52.95.252.0/23 */
    {0x345ffe00u, PROTO_AWS, 24}, /* 52.95.254.0/24 */
    {0x345fff00u, PROTO_AWS, 25}, /* 52.95.255.0/25 */
    {0x345fff80u, PROTO_AWS, 28}, /* 52.95.255.128/28 */
    {0x345fff90u, PROTO_UNKNOWN, 0},
    {0x34600b00u, PROTO_AZURE, 24}, /* 52.96.11.0/24 */
    {0x34600c00u, PROTO_UNKNOWN, 0},
    {0x34650000u, PROTO_AZURE, 16}, /* 52.101.0.0/16 */
    {0x34660000u, PROTO_UNKNOWN, 0},
    {0x34668000u, PROTO_AZURE, 17}, /* 52.102.128.0/17 */
    {0x34670000u, PROTO_AZURE, 16}, /* 52.103.0.0/16 */
    {0x34680000u, PROTO_UNKNOWN, 0},
    {0x346a0000u, PROTO_AZURE, 16}, /* 52.106.0.0/16 */
    {0x346b0000u, PROTO_UNKNOWN, 0},
    {0x346c0000u, PROTO_AZURE, 21}, /* 52.108.0.0/21 */
    {0x346c0800u, PROTO_UNKNOWN, 0},
    {0x346c1000u, PROTO_AZURE, 20}, /* 52.108.16.0/20 */
    {0x346c2000u, PROTO_AZURE, 19}, /* 52.108.32.0/19 */
    {0x346c4000u, PROTO_UNKNOWN, 0},
    {0x346c4400u, PROTO_AZURE, 22}, /* 52.108.68.0/22 */
    {0x346c4800u, PROTO_AZURE, 21}, /* 52.108.72.0/21 */
    {0x346c5000u, PROTO_AZURE, 20}, /* 52.108.80.0/20 */
    {0x346c7000u, PROTO_AZURE, 23}, /* 52.108.112.0/23 */
    {0x346c7200u, PROTO_UNKNOWN, 0},
    {0x346c7300u, PROTO_AZURE, 24}, /* 52.108.115.0/24 */
    {0x346c7400u, PROTO_AZURE, 23}, /* 52.108.116.0/23 */
    {0x346c7600u, PROTO_AZURE, 24}, /* 52.108.118.0/24 */
    {0x346c7700u, PROTO_UNKNOWN, 0},
    {0x346c7900u, PROTO_AZURE, 24}, /* 52.108.121.0/24 */
    {0x346c7a00u, PROTO_AZURE, 23}, /* 52.108.122.0/23 */
    {0x346c7c00u, PROTO_AZURE, 22}, /* 52.108.124.0/22 */
    {0x346c8000u, PROTO_AZURE, 21}, /* 52.108.128.0/21 */
    {0x346c8800u, PROTO_AZURE, 22}, /* 52.108.136.0/22 */
    {0x346c8c00u, PROTO_UNKNOWN, 0},
    {0x346c9000u, PROTO_AZURE, 21}, /* 52.108.144.0/21 */
    {0x346c9800u, PROTO_AZURE, 22}, /* 52.108.152.0/22 */
    {0x346c9c00u, PROTO_AZURE, 24}, /* 52.108.156.0/24 */
    {0x346c9d00u, PROTO_UNKNOWN, 0},
    {0x346ca500u, PROTO_AZURE, 24}, /* 52.108.165.0/24 */
    {0x346ca600u, PROTO_AZURE, 23}, /* 52.108.166.0/23 */
    {0x346ca800u, PROTO_AZURE, 21}, /* 52.108.168.0/21 */
    {0x346cb000u, PROTO_AZURE, 20}, /* 52.108.176.0/20 */
    {0x346cc000u, PROTO_AZURE, 18}, /* 52.108.192.0/18 */
    {0x346d0000u, PROTO_AZURE, 16}, /* 52.109.0.0/16 */
    {0x346e0000u, PROTO_UNKNOWN, 0},
    {0x346fc000u, PROTO_AZURE, 20}, /* 52.111.192.0/20 */
    {0x346fd000u, PROTO_AZURE, 22}, /* 52.111.208.0/22 */
    {0x346fd400u, PROTO_UNKNOWN, 0},
    {0x346fe000u, PROTO_AZURE, 19}, /* 52.111.224.0/19 */
    {0x34700000u, PROTO_AZURE, 20}, /* 52.112.0.0/20 */
    {0x34701000u, PROTO_AZURE, 22}, /* 52.112.16.0/22 */
    {0x34701400u, PROTO_UNKNOWN, 0},
    {0x34701600u, PROTO_AZURE, 23}, /* 52.112.22.0/23 */
    {0x34701a00u, PROTO_AZURE, 24}, /* 52.112.26.0/24 */
    {0x34701b00u, PROTO_UNKNOWN, 0},
    {0x34702000u, PROTO_AZURE, 24}, /* 52.112.32.0/24 */
    {0x34702100u, PROTO_UNKNOWN, 0},
    {0x34702200u, PROTO_AZURE, 23}, /* 52.112.34.0/23 */
    {0x34702400u, PROTO_AZURE, 22}, /* 52.112.36.0/22 */
    {0x34702800u, PROTO_AZURE, 21}, /* 52.112.40.0/21 */
    {0x34703000u, PROTO_AZURE, 20}, /* 52.112.48.0/20 */
    {0x34704000u, PROTO_UNKNOWN, 0},
    {0x34704100u, PROTO_AZURE, 24}, /* 52.112.65.0/24 */
    {0x34704300u, PROTO_UNKNOWN, 0},
    {0x34704400u, PROTO_AZURE, 23}, /* 52.112.68.0/23 */
    {0x34704600u, PROTO_AZURE, 24}, /* 52.112.70.0/24 */
    {0x34704700u, PROTO_UNKNOWN, 0},
    {0x34704800u, PROTO_AZURE, 21}, /* 52.112.72.0/21 */
    {0x34705000u, PROTO_UNKNOWN, 0},
    {0x34705400u, PROTO_AZURE, 22}, /* 52.112.84.0/22 */
    {0x34705800u, PROTO_AZURE, 21}, /* 52.112.88.0/21 */
    {0x34706000u, PROTO_AZURE, 24}, /* 52.112.96.0/24 */
    {0x34706100u, PROTO_UNKNOWN, 0},
    {0x34706400u, PROTO_AZURE, 22}, /* 52.112.100.0/22 */
    {0x34706800u, PROTO_UNKNOWN, 0},
    {0x34706900u, PROTO_AZURE, 24}, /* 52.112.105.0/24 */
    {0x34706a00u, PROTO_AZURE, 23}, /* 52.112.106.0/23 */
    {0x34706e00u, PROTO_UNKNOWN, 0},
    {0x34707000u, PROTO_AZURE, 21}, /* 52.112.112.0/21 */
    {0x34707800u, PROTO_AZURE, 24}, /* 52.112.120.0/24 */
    {0x34707900u, PROTO_UNKNOWN, 0},
    {0x34707a00u, PROTO_AZURE, 23}, /* 52.112.122.0/23 */
    {0x34707c00u, PROTO_AZURE, 22}, /* 52.112.124.0/22 */
    {0x34708000u, PROTO_AZURE, 18}, /* 52.112.128.0/18 */
    {0x3470c000u, PROTO_AZURE, 19}, /* 52.112.192.0/19 */
    {0x3470e000u, PROTO_AZURE, 22}, /* 52.112.224.0/22 */
    {0x3470e400u, PROTO_AZURE, 23}, /* 52.112.228.0/23 */
    {0x3470e600u, PROTO_UNKNOWN, 0},
    {0x3470e700u, PROTO_AZURE, 24}, /* 52.112.231.0/24 */
    {0x3470e800u, PROTO_AZURE, 21}, /* 52.112.232.0/21 */
    {0x3470f000u, PROTO_AZURE, 20}, /* 52.112.240.0/20 */
    {0x34710000u, PROTO_AZURE, 21}, /* 52.113.0.0/21 */
    {0x34710800u, PROTO_AZURE, 22}, /* 52.113.8.0/22 */
    {0x34710c00u, PROTO_AZURE, 24}, /* 52.113.12.0/24 */
    {0x34710d00u, PROTO_UNKNOWN, 0},
    {0x34710e00u, PROTO_AZURE, 24}, /* 52.113.14.0/24 */
    {0x34710f00u, PROTO_UNKNOWN, 0},
    {0x34711000u, PROTO_AZURE, 20}, /* 52.113.16.0/20 */
    {0x34712000u, PROTO_AZURE, 19}, /* 52.113.32.0/19 */
    {0x34716000u, PROTO_UNKNOWN, 0},
    {0x34716500u, PROTO_AZURE, 24}, /* 52.113.101.0/24 */
    {0x34716600u, PROTO_AZURE, 23}, /* 52.113.102.0/23 */
    {0x34716800u, PROTO_UNKNOWN, 0},
    {0x34716a00u, PROTO_AZURE, 23}, /* 52.113.106.0/23 */
    {0x34716c00u, PROTO_AZURE, 22}, /* 52.113.108.0/22 */
    {0x34717000u, PROTO_AZURE, 20}, /* 52.113.112.0/20 */
    {0x34718000u, PROTO_AZURE, 23}, /* 52.113.128.0/23 */
    {0x34718200u, PROTO_UNKNOWN, 0},
    {0x34718300u, PROTO_AZURE, 24}, /* 52.113.131.0/24 */
    {0x34718400u, PROTO_AZURE, 22}, /* 52.113.132.0/22 */
    {0x34718800u, PROTO_AZURE, 21}, /* 52.113.136.0/21 */
    {0x34719000u, PROTO_AZURE, 20}, /* 52.113.144.0/20 */
    {0x3471a000u, PROTO_AZURE, 19}, /* 52.113.160.0/19 */
    {0x3471c000u, PROTO_AZURE, 23}, /* 52.113.192.0/23 */
    {0x3471c200u, PROTO_UNKNOWN, 0},
    {0x3471c600u, PROTO_AZURE, 23}, /* 52.113.198.0/23 */
    {0x3471c800u, PROTO_AZURE, 21}, /* 52.113.200.0/21 */
    {0x3471d000u, PROTO_AZURE, 20}, /* 52.113.208.0/20 */
    {0x3471e000u, PROTO_AZURE, 19}, /* 52.113.224.0/19 */
    {0x34720000u, PROTO_AZURE, 18}, /* 52.114.0.0/18 */
    {0x34724000u, PROTO_UNKNOWN, 0},
    {0x34724100u, PROTO_AZURE, 24}, /* 52.114.65.0/24 */
    {0x34724200u, PROTO_UNKNOWN, 0},
    {0x34724300u, PROTO_AZURE, 24}, /* 52.114.67.0/24 */
    {0x34724400u, PROTO_UNKNOWN, 0},
    {0x34724500u, PROTO_AZURE, 24}, /* 52.114.69.0/24 */
    {0x34724600u, PROTO_UNKNOWN, 0},
    {0x34724700u, PROTO_AZURE, 24}, /* 52.114.71.0/24 */
    {0x34724800u, PROTO_AZURE, 21}, /* 52.114.72.0/21 */
    {0x34725000u, PROTO_AZURE, 20}, /* 52.114.80.0/20 */
    {0x34726000u, PROTO_AZURE, 22}, /* 52.114.96.0/22 */
    {0x34726400u, PROTO_AZURE, 24}, /* 52.114.100.0/24 */
    {0x34726500u, PROTO_UNKNOWN, 0},
    {0x34726800u, PROTO_AZURE, 21}, /* 52.114.104.0/21 */
    {0x34727000u, PROTO_AZURE, 22}, /* 52.114.112.0/22 */
    {0x34727400u, PROTO_UNKNOWN, 0},
    {0x34727800u, PROTO_AZURE, 24}, /* 52.114.120.0/24 */
    {0x34727900u, PROTO_UNKNOWN, 0},
    {0x34727a00u, PROTO_AZURE, 24}, /* 52.114.122.0/24 */
    {0x34727b00u, PROTO_UNKNOWN, 0},
    {0x34727c00u, PROTO_AZURE, 24}, /* 52.114.124.0/24 */
    {0x34727d00u, PROTO_UNKNOWN, 0},
    {0x34727e00u, PROTO_AZURE, 24}, /* 52.114.126.0/24 */
    {0x34727f00u, PROTO_UNKNOWN, 0},
    {0x34728000u, PROTO_AZURE, 18}, /* 52.114.128.0/18 */
    {0x3472c000u, PROTO_AZURE, 21}, /* 52.114.192.0/21 */
    {0x3472c800u, PROTO_AZURE, 22}, /* 52.114.200.0/22 */
    {0x3472cc00u, PROTO_UNKNOWN, 0},
    {0x3472cd00u, PROTO_AZURE, 24}, /* 52.114.205.0/24 */
    {0x3472ce00u, PROTO_AZURE, 23}, /* 52.114.206.0/23 */
    {0x3472d000u, PROTO_AZURE, 20}, /* 52.114.208.0/20 */
    {0x3472e000u, PROTO_AZURE, 19}, /* 52.114.224.0/19 */
    {0x34730000u, PROTO_AZURE, 18}, /* 52.115.0.0/18 */
    {0x34734000u, PROTO_UNKNOWN, 0},
    {0x34734100u, PROTO_AZURE, 24}, /* 52.115.65.0/24 */
    {0x34734200u, PROTO_AZURE, 23}, /* 52.115.66.0/23 */
    {0x34734400u, PROTO_AZURE, 22}, /* 52.115.68.0/22 */
    {0x34734800u, PROTO_AZURE, 21}, /* 52.115.72.0/21 */
    {0x34735800u, PROTO_AZURE, 22}, /* 52.115.88.0/22 */
    {0x34735c00u, PROTO_AZURE, 23}, /* 52.115.92.0/23 */
    {0x34735e00u, PROTO_AZURE, 24}, /* 52.115.94.0/24 */
    {0x34735f00u, PROTO_UNKNOWN, 0},
    {0x34736000u, PROTO_AZURE, 20}, /* 52.115.96.0/20 */
    {0x34737000u, PROTO_AZURE, 22}, /* 52.115.112.0/22 */
    {0x34737400u, PROTO_AZURE, 23}, /* 52.115.116.0/23 */
    {0x34737600u, PROTO_UNKNOWN, 0},
    {0x34737700u, PROTO_AZURE, 24}, /* 52.115.119.0/24 */
    {0x34737800u, PROTO_UNKNOWN, 0},
    {0x34737900u, PROTO_AZURE, 24}, /* 52.115.121.0/24 */
    {0x34737a00u, PROTO_UNKNOWN, 0},
    {0x34737b00u, PROTO_AZURE, 24}, /* 52.115.123.0/24 */
    {0x34737c00u, PROTO_UNKNOWN, 0},
    {0x34737d00u, PROTO_AZURE, 24}, /* 52.115.125.0/24 */
    {0x34737e00u, PROTO_UNKNOWN, 0},
    {0x34737f00u, PROTO_AZURE, 24}, /* 52.115.127.0/24 */
    {0x34738000u, PROTO_AZURE, 18}, /* 52.115.128.0/18 */
    {0x3473c000u, PROTO_AZURE, 19}, /* 52.115.192.0/19 */
    {0x3473e000u, PROTO_AZURE, 20}, /* 52.115.224.0/20 */
    {0x3473f000u, PROTO_AZURE, 21}, /* 52.115.240.0/21 */
    {0x3473f800u, PROTO_UNKNOWN, 0},
    {0x34778000u, PROTO_AWS, 18}, /* 52.119.128.0/18 */
    {0x3477c000u, PROTO_AWS, 21}, /* 52.119.192.0/21 */
    {0x3477c800u, PROTO_UNKNOWN, 0},
    {0x3477cd00u, PROTO_AWS, 24}, /* 52.119.205.0/24 */
    {0x3477ce00u, PROTO_AWS, 23}, /* 52.119.206.0/23 */
    {0x3477d000u, PROTO_AWS, 20}, /* 52.119.208.0/20 */
    {0x3477f000u, PROTO_AWS, 21}, /* 52.119.240.0/21 */
    {0x3477f800u, PROTO_AWS, 23}, /* 52.119.248.0/23 */
    {0x3477fa00u, PROTO_UNKNOWN, 0},
    {0x3477fc00u, PROTO_AWS, 22}, /* 52.119.252.0/22 */
    {0x34780000u, PROTO_AZURE, 15}, /* 52.120.0.0/15 */
    {0x347a0000u, PROTO_AZURE, 16}, /* 52.122.0.0/16 */
    {0x347b0000u, PROTO_AZURE, 17}, /* 52.123.0.0/17 */
    {0x347b8000u, PROTO_UNKNOWN, 0},
    {0x347b8400u, PROTO_AZURE, 22}, /* 52.123.132.0/22 */
    {0x347b8800u, PROTO_AZURE, 21}, /* 52.123.136.0/21 */
    {0x347b9000u, PROTO_AZURE, 20}, /* 52.123.144.0/20 */
    {0x347ba000u, PROTO_AZURE, 19}, /* 52.123.160.0/19 */
    {0x347bc000u, PROTO_AZURE, 22}, /* 52.123.192.0/22 */
    {0x347bc400u, PROTO_UNKNOWN, 0},
    {0x347bc600u, PROTO_AZURE, 23}, /* 52.123.198.0/23 */
    {0x347bca00u, PROTO_UNKNOWN, 0},
    {0x347bcc00u, PROTO_AZURE, 22}, /* 52.123.204.0/22 */
    {0x347bd000u, PROTO_AZURE, 20}, /* 52.123.208.0/20 */
    {0x347be000u, PROTO_UNKNOWN, 0},
    {0x347c8000u, PROTO_CLOUDFRONT, 17}, /* 52.124.128.0/17 */
    {0x347d0000u, PROTO_UNKNOWN, 0},
    {0x347d8000u, PROTO_AZURE, 20}, /* 52.125.128.0/20 */
    {0x347d9000u, PROTO_UNKNOWN, 0},
    {0x34818200u, PROTO_AWS, 23}, /* 52.129.130.0/23 */
    {0x34818400u, PROTO_UNKNOWN, 0},
    {0x3481e000u, PROTO_AWS, 22}, /* 52.129.224.0/22 */
    {0x3481e400u, PROTO_UNKNOWN, 0},
    {0x34880000u, PROTO_AZURE, 13}, /* 52.136.0.0/13 */
    {0x34900000u, PROTO_UNKNOWN, 0},
    {0x34908520u, PROTO_AWS, 27}, /* 52.144.133.32/27 */
    {0x34908540u, PROTO_UNKNOWN, 0},
    {0x3490c000u, PROTO_AWS, 24}, /* 52.144.192.0/24 */
    {0x3490c100u, PROTO_AWS, 25}, /* 52.144.193.0/25 */
    {0x3490c180u, PROTO_AWS, 26}, /* 52.144.193.128/26 */
    {0x3490c1c0u, PROTO_UNKNOWN, 0},
    {0x3490c200u, PROTO_AWS, 24}, /* 52.144.194.0/24 */
    {0x3490c300u, PROTO_AWS, 26}, /* 52.144.195.0/26 */
    {0x3490c340u, PROTO_UNKNOWN, 0},
    {0x3490c4c0u, PROTO_AWS, 26}, /* 52.144.196.192/26 */
    {0x3490c500u, PROTO_UNKNOWN, 0},
    {0x3490c580u, PROTO_AWS, 25}, /* 52.144.197.128/25 */
    {0x3490c600u, PROTO_UNKNOWN, 0},
    {0x3490c780u, PROTO_AWS, 26}, /* 52.144.199.128/26 */
    {0x3490c7c0u, PROTO_UNKNOWN, 0},
    {0x3490c840u, PROTO_AWS, 26}, /* 52.144.200.64/26 */
    {0x3490c8c0u, PROTO_UNKNOWN, 0},
    {0x3490c940u, PROTO_AWS, 26}, /* 52.144.201.64/26 */
    {0x3490c9c0u, PROTO_UNKNOWN, 0},
    {0x3490cd00u, PROTO_AWS, 26}, /* 52.144.205.0/26 */
    {0x3490cd40u, PROTO_UNKNOWN, 0},
    {0x3490d000u, PROTO_AWS, 30}, /* 52.144.208.0/30 */
    {0x3490d004u, PROTO_UNKNOWN, 0},
    {0x3490d040u, PROTO_AWS, 26}, /* 52.144.208.64/26 */
    {0x3490d080u, PROTO_AWS, 25}, /* 52.144.208.128/25 */
    {0x3490d100u, PROTO_AWS, 24}, /* 52.144.209.0/24 */
    {0x3490d300u, PROTO_AWS, 25}, /* 52.144.211.0/25 */
    {0x3490d380u, PROTO_AWS, 26}, /* 52.144.211.128/26 */
    {0x3490d3c0u, PROTO_AWS, 29}, /* 52.144.211.192/29 */
    {0x3490d3c8u, PROTO_AWS, 30}, /* 52.144.211.200/30 */
    {0x3490d3ccu, PROTO_UNKNOWN, 0},
    {0x3490d440u, PROTO_AWS, 26}, /* 52.144.212.64/26 */
    {0x3490d480u, PROTO_UNKNOWN, 0},
    {0x3490d4c0u, PROTO_AWS, 26}, /* 52.144.212.192/26 */
    {0x3490d500u, PROTO_UNKNOWN, 0},
    {0x3490d540u, PROTO_AWS, 26}, /* 52.144.213.64/26 */
    {0x3490d580u, PROTO_UNKNOWN, 0},
    {0x3490d680u, PROTO_AWS, 26}, /* 52.144.214.128/26 */
    {0x3490d6c0u, PROTO_UNKNOWN, 0},
    {0x3490d700u, PROTO_AWS, 30}, /* 52.144.215.0/30 */
    {0x3490d704u, PROTO_UNKNOWN, 0},
    {0x3490d7c0u, PROTO_AWS, 29}, /* 52.144.215.192/29 */
    {0x3490d7c8u, PROTO_AWS, 30}, /* 52.144.215.200/30 */
    {0x3490d7ccu, PROTO_UNKNOWN, 0},
    {0x3490d800u, PROTO_AWS, 29}, /* 52.144.216.0/29 */
    {0x3490d808u, PROTO_AWS, 30}, /* 52.144.216.8/30 */
    {0x3490d80cu, PROTO_UNKNOWN, 0},
    {0x3490da00u, PROTO_AWS, 25}, /* 52.144.218.0/25 */
    {0x3490da80u, PROTO_UNKNOWN, 0},
    {0x3490df40u, PROTO_AWS, 26}, /* 52.144.223.64/26 */
    {0x3490dfc0u, PROTO_UNKNOWN, 0},
    {0x3490e040u, PROTO_AWS, 26}, /* 52.144.224.64/26 */
    {0x3490e080u, PROTO_AWS, 25}, /* 52.144.224.128/25 */
    {0x3490e180u, PROTO_AWS, 26}, /* 52.144.225.128/26 */
    {0x3490e1c0u, PROTO_UNKNOWN, 0},
    {0x3490e340u, PROTO_AWS, 26}, /* 52.144.227.64/26 */
    {0x3490e380u, PROTO_UNKNOWN, 0},
    {0x3490e3c0u, PROTO_AWS, 26}, /* 52.144.227.192/26 */
    {0x3490e400u, PROTO_AWS, 30}, /* 52.144.228.0/30 */
    {0x3490e404u, PROTO_UNKNOWN, 0},
    {0x3490e440u, PROTO_AWS, 26}, /* 52.144.228.64/26 */
    {0x3490e480u, PROTO_AWS, 25}, /* 52.144.228.128/25 */
    {0x3490e580u, PROTO_UNKNOWN, 0},
    {0x3490e600u, PROTO_AWS, 26}, /* 52.144.230.0/26 */
    {0x3490e640u, PROTO_UNKNOWN, 0},
    {0x3490e6ccu, PROTO_AWS, 30}, /* 52.144.230.204/30 */
    {0x3490e6d4u, PROTO_UNKNOWN, 0},
    {0x3490e740u, PROTO_AWS, 26}, /* 52.144.231.64/26 */
    {0x3490e780u, PROTO_UNKNOWN, 0},
    {0x3490e940u, PROTO_AWS, 29}, /* 52.144.233.64/29 */
    {0x3490e948u, PROTO_UNKNOWN, 0},
    {0x3490e980u, PROTO_AWS, 29}, /* 52.144.233.128/29 */
    {0x3490e988u, PROTO_UNKNOWN, 0},
    {0x3490e9c0u, PROTO_AWS, 26}, /* 52.144.233.192/26 */
    {0x3490ea00u, PROTO_UNKNOWN, 0},
    {0x34920000u, PROTO_AZURE, 15}, /* 52.146.0.0/15 */
    {0x34940000u, PROTO_AZURE, 14}, /* 52.148.0.0/14 */
    {0x34980000u, PROTO_AZURE, 13}, /* 52.152.0.0/13 */
    {0x34a00000u, PROTO_AZURE, 12}, /* 52.160.0.0/12 */
    {0x34b00000u, PROTO_AZURE, 14}, /* 52.176.0.0/14 */
    {0x34b40000u, PROTO_AZURE, 17}, /* 52.180.0.0/17 */
    {0x34b48000u, PROTO_AZURE, 18}, /* 52.180.128.0/18 */
    {0x34b4c000u, PROTO_UNKNOWN, 0},
    {0x34b68000u, PROTO_AZURE, 17}, /* 52.182.128.0/17 */
    {0x34b70000u, PROTO_AZURE, 16}, /* 52.183.0.0/16 */
    {0x34b80000u, PROTO_AZURE, 13}, /* 52.184.0.0/13 */
    {0x34c00000u, PROTO_AWS, 14}, /* 52.192.0.0/14 */
    {0x34c40000u, PROTO_AWS, 15}, /* 52.196.0.0/15 */
    {0x34c60000u, PROTO_AWS, 16}, /* 52.198.0.0/16 */
    {0x34c70000u, PROTO_AWS, 18}, /* 52.199.0.0/18 */
    {0x34c74000u, PROTO_AWS, 19}, /* 52.199.64.0/19 */
    {0x34c76000u, PROTO_AWS, 20}, /* 52.199.96.0/20 */
    {0x34c77000u, PROTO_AWS, 21}, /* 52.199.112.0/21 */
    {0x34c77800u, PROTO_AWS, 22}, /* 52.199.120.0/22 */
    {0x34c77c00u, PROTO_AWS, 23}, /* 52.199.124.0/23 */
    {0x34c77e00u, PROTO_AWS, 24}, /* 52.199.126.0/24 */
    {0x34c77f00u, PROTO_AWS, 25}, /* 52.199.127.0/25 */
    {0x34c77f80u, PROTO_AWS, 26}, /* 52.199.127.128/26 */
    {0x34c77fc0u, PROTO_CLOUDFRONT, 26}, /* 52.199.127.192/26 */
    {0x34c78000u, PROTO_AWS, 17}, /* 52.199.128.0/17 */
    {0x34c80000u, PROTO_AWS, 13}, /* 52.200.0.0/13 */
    {0x34d00000u, PROTO_AWS, 14}, /* 52.208.0.0/14 */
    {0x34d40000u, PROTO_AWS, 17}, /* 52.212.0.0/17 */
    {0x34d48000u, PROTO_AWS, 18}, /* 52.212.128.0/18 */
    {0x34d4c000u, PROTO_AWS, 19}, /* 52.212.192.0/19 */
    {0x34d4e000u, PROTO_AWS, 20}, /* 52.212.224.0/20 */
    {0x34d4f000u, PROTO_AWS, 21}, /* 52.212.240.0/21 */
    {0x34d4f800u, PROTO_CLOUDFRONT, 26}, /* 52.212.248.0/26 */
    {0x34d4f840u, PROTO_AWS, 26}, /* 52.212.248.64/26 */
    {0x34d4f880u, PROTO_AWS, 25}, /* 52.212.248.128/25 */
    {0x34d4f900u, PROTO_AWS, 24}, /* 52.212.249.0/24 */
    {0x34d4fa00u, PROTO_AWS, 23}, /* 52.212.250.0/23 */
    {0x34d4fc00u, PROTO_AWS, 22}, /* 52.212.252.0/22 */
    {0x34d50000u, PROTO_AWS, 16}, /* 52.213.0.0/16 */
    {0x34d60000u, PROTO_AWS, 15}, /* 52.214.0.0/15 */
    {0x34da0000u, PROTO_AWS, 16}, /* 52.218.0.0/16 */
    {0x34db0000u, PROTO_AWS, 20}, /* 52.219.0.0/20 */
    {0x34db1000u, PROTO_AWS, 22}, /* 52.219.16.0/22 */
    {0x34db1400u, PROTO_AWS, 23}, /* 52.219.20.0/23 */
    {0x34db1600u, PROTO_UNKNOWN, 0},
    {0x34db1700u, PROTO_AWS, 24}, /* 52.219.23.0/24 */
    {0x34db1800u, PROTO_AWS, 21}, /* 52.219.24.0/21 */
    {0x34db2000u, PROTO_AWS, 20}, /* 52.219.32.0/20 */
    {0x34db3000u, PROTO_UNKNOWN, 0},
    {0x34db3800u, PROTO_AWS, 21}, /* 52.219.56.0/21 */
    {0x34db4800u, PROTO_AWS, 22}, /* 52.219.72.0/22 */
    {0x34db4c00u, PROTO_UNKNOWN, 0},
    {0x34db5000u, PROTO_AWS, 20}, /* 52.219.80.0/20 */
    {0x34db6000u, PROTO_AWS, 19}, /* 52.219.96.0/19 */
    {0x34db8000u, PROTO_AWS, 18}, /* 52.219.128.0/18 */
    {0x34dbc000u, PROTO_AWS, 20}, /* 52.219.192.0/20 */
    {0x34dbd000u, PROTO_AWS, 21}, /* 52.219.208.0/21 */
    {0x34dbd800u, PROTO_AWS, 22}, /* 52.219.216.0/22 */
    {0x34dbdc00u, PROTO_AWS, 23}, /* 52.219.220.0/23 */
    {0x34dbde00u, PROTO_UNKNOWN, 0},
    {0x34dbe000u, PROTO_AWS, 21}, /* 52.219.224.0/21 */
    {0x34dbe800u, PROTO_AWS, 22}, /* 52.219.232.0/22 */
    {0x34dbec00u, PROTO_UNKNOWN, 0},
    {0x34dbfe00u, PROTO_AWS, 23}, /* 52.219.254.0/23 */
    {0x34dc0000u, PROTO_AWS, 17}, /* 52.220.0.0/17 */
    {0x34dc8000u, PROTO_AWS, 19}, /* 52.220.128.0/19 */
    {0x34dca000u, PROTO_AWS, 20}, /* 52.220.160.0/20 */
    {0x34dcb000u, PROTO_AWS, 21}, /* 52.220.176.0/21 */
    {0x34dcb800u, PROTO_AWS, 22}, /* 52.220.184.0/22 */
    {0x34dcbc00u, PROTO_AWS, 23}, /* 52.220.188.0/23 */
    {0x34dcbe00u, PROTO_AWS, 24}, /* 52.220.190.0/24 */
    {0x34dcbf00u, PROTO_CLOUDFRONT, 26}, /* 52.220.191.0/26 */
    {0x34dcbf40u, PROTO_AWS, 26}, /* 52.220.191.64/26 */
    {0x34dcbf80u, PROTO_AWS, 25}, /* 52.220.191.128/25 */
    {0x34dcc000u, PROTO_AWS, 18}, /* 52.220.192.0/18 */
    {0x34dd0000u, PROTO_AWS, 16}, /* 52.221.0.0/16 */
    {0x34de0000u, PROTO_AWS, 17}, /* 52.222.0.0/17 */
    {0x34de8000u, PROTO_CLOUDFRONT, 17}, /* 52.222.128.0/17 */
    {0x34df0000u, PROTO_AWS, 17}, /* 52.223.0.0/17 */
    {0x34df8000u, PROTO_UNKNOWN, 0},
    {0x34dfc000u, PROTO_AWS, 18}, /* 52.223.192.0/18 */
    {0x34e00000u, PROTO_AZURE, 15}, /* 52.224.0.0/15 */
    {0x34e20000u, PROTO_AZURE, 16}, /* 52.226.0.0/16 */
    {0x34e30000u, PROTO_UNKNOWN, 0},
    {0x34e40000u, PROTO_AZURE, 14}, /* 52.228.0.0/14 */
    {0x34e80000u, PROTO_AZURE, 15}, /* 52.232.0.0/15 */
    {0x34ea0000u, PROTO_AZURE, 16}, /* 52.234.0.0/16 */
    {0x34eb0000u, PROTO_AZURE, 17}, /* 52.235.0.0/17 */
    {0x34eb8000u, PROTO_UNKNOWN, 0},
    {0x34ec0000u, PROTO_AZURE, 15}, /* 52.236.0.0/15 */
    {0x34ee0000u, PROTO_AZURE, 18}, /* 52.238.0.0/18 */
    {0x34ee4000u, PROTO_UNKNOWN, 0},
    {0x34eec000u, PROTO_AZURE, 18}, /* 52.238.192.0/18 */
    {0x34ef0000u, PROTO_AZURE, 17}, /* 52.239.0.0/17 */
    {0x34ef8000u, PROTO_AZURE, 19}, /* 52.239.128.0/19 */
    {0x34efa000u, PROTO_AZURE, 22}, /* 52.239.160.0/22 */
    {0x34efa400u, PROTO_AZURE, 23}, /* 52.239.164.0/23 */
    {0x34efa600u, PROTO_UNKNOWN, 0},
    {0x34efa700u, PROTO_AZURE, 24}, /* 52.239.167.0/24 */
    {0x34efa800u, PROTO_AZURE, 21}, /* 52.239.168.0/21 */
    {0x34efb000u, PROTO_UNKNOWN, 0},
    {0x34efb080u, PROTO_AZURE, 25}, /* 52.239.176.128/25 */
    {0x34efb100u, PROTO_AZURE, 24}, /* 52.239.177.0/24 */
    {0x34efb200u, PROTO_AZURE, 23}, /* 52.239.178.0/23 */
    {0x34efb400u, PROTO_AZURE, 22}, /* 52.239.180.0/22 */
    {0x34efbc00u, PROTO_AZURE, 23}, /* 52.239.188.0/23 */
    {0x34efbe00u, PROTO_AZURE, 24}, /* 52.239.190.0/24 */
    {0x34efbf00u, PROTO_AZURE, 28}, /* 52.239.191.0/28 */
    {0x34efbf10u, PROTO_UNKNOWN, 0},
    {0x34efc000u, PROTO_AZURE, 18}, /* 52.239.192.0/18 */
    {0x34f00000u, PROTO_AZURE, 15}, /* 52.240.0.0/15 */
    {0x34f20000u, PROTO_AZURE, 16}, /* 52.242.0.0/16 */
    {0x34f30000u, PROTO_UNKNOWN, 0},
    {0x34f32000u, PROTO_AZURE, 19}, /* 52.243.32.0/19 */
    {0x34f34000u, PROTO_AZURE, 18}, /* 52.243.64.0/18 */
    {0x34f38000u, PROTO_UNKNOWN, 0},
    {0x34f50800u, PROTO_AZURE, 21}, /* 52.245.8.0/21 */
    {0x34f51000u, PROTO_AZURE, 20}, /* 52.245.16.0/20 */
    {0x34f52000u, PROTO_AZURE, 19}, /* 52.245.32.0/19 */
    {0x34f54000u, PROTO_AZURE, 18}, /* 52.245.64.0/18 */
    {0x34f58000u, PROTO_UNKNOWN, 0},
    {0x34f60000u, PROTO_AZURE, 17}, /* 52.246.0.0/17 */
    {0x34f68000u, PROTO_AZURE, 20}, /* 52.246.128.0/20 */
    {0x34f69000u, PROTO_UNKNOWN, 0},
    {0x34f69800u, PROTO_AZURE, 21}, /* 52.246.152.0/21 */
    {0x34f6a000u, PROTO_AZURE, 19}, /* 52.246.160.0/19 */
    {0x34f6c000u, PROTO_AZURE, 18}, /* 52.246.192.0/18 */
    {0x34f70000u, PROTO_AZURE, 17}, /* 52.247.0.0/17 */
    {0x34f78000u, PROTO_UNKNOWN, 0},
    {0x34f7c000u, PROTO_AZURE, 18}, /* 52.247.192.0/18 */
    {0x34f80000u, PROTO_AZURE, 16}, /* 52.248.0.0/16 */
    {0x34f90000u, PROTO_AZURE, 18}, /* 52.249.0.0/18 */
    {0x34f94000u, PROTO_AZURE, 19}, /* 52.249.64.0/19 */
    {0x34f96000u, PROTO_UNKNOWN, 0},
    {0x34f98000u, PROTO_AZURE, 17}, /* 52.249.128.0/17 */
    {0x34fa0000u, PROTO_AZURE, 16}, /* 52.250.0.0/16 */
    {0x34fb0000u, PROTO_AZURE, 17}, /* 52.251.0.0/17 */
    {0x34fb8000u, PROTO_AZURE, 22}, /* 52.251.128.0/22 */
    {0x34fb8400u, PROTO_UNKNOWN, 0},
    {0x34fc0000u, PROTO_AZURE, 16}, /* 52.252.0.0/16 */
    {0x34fd0000u, PROTO_AZURE, 17}, /* 52.253.0.0/17 */
    {0x34fd8000u, PROTO_AZURE, 20}, /* 52.253.128.0/20 */
    {0x34fd9000u, PROTO_UNKNOWN, 0},
    {0x34fd9400u, PROTO_AZURE, 22}, /* 52.253.148.0/22 */
    {0x34fd9800u, PROTO_AZURE, 21}, /* 52.253.152.0/21 */
    {0x34fda000u, PROTO_AZURE, 19}, /* 52.253.160.0/19 */
    {0x34fde000u, PROTO_AZURE, 20}, /* 52.253.224.0/20 */
    {0x34fdf000u, PROTO_UNKNOWN, 0},
    {0x34fe0000u, PROTO_AZURE, 15}, /* 52.254.0.0/15 */
    {0x35000000u, PROTO_UNKNOWN, 0},
    {0x36050000u, PROTO_AWS, 16}, /* 54.5.0.0/16 */
    {0x36060000u, PROTO_AWS, 15}, /* 54.6.0.0/15 */
    {0x36080000u, PROTO_AWS, 16}, /* 54.8.0.0/16 */
    {0x36090000u, PROTO_UNKNOWN, 0},
    {0x36140000u, PROTO_AWS, 15}, /* 54.20.0.0/15 */
    {0x36160000u, PROTO_UNKNOWN, 0},
    {0x36190000u, PROTO_AWS, 21}, /* 54.25.0.0/21 */
    {0x36190800u, PROTO_UNKNOWN, 0},
    {0x36190e00u, PROTO_AWS, 23}, /* 54.25.14.0/23 */
    {0x36191000u, PROTO_UNKNOWN, 0},
    {0x36191400u, PROTO_AWS, 24}, /* 54.25.20.0/24 */
    {0x36191500u, PROTO_UNKNOWN, 0},
    {0x36192000u, PROTO_AWS, 19}, /* 54.25.32.0/19 */
    {0x36194000u, PROTO_UNKNOWN, 0},
    {0x36195200u, PROTO_AWS, 24}, /* 54.25.82.0/24 */
    {0x36195300u, PROTO_UNKNOWN, 0},
    {0x3619c000u, PROTO_AWS, 18}, /* 54.25.192.0/18 */
    {0x361a0000u, PROTO_UNKNOWN, 0},
    {0x361aa600u, PROTO_AWS, 24}, /* 54.26.166.0/24 */
    {0x361aa700u, PROTO_UNKNOWN, 0},
    {0x36200000u, PROTO_AWS, 15}, /* 54.32.0.0/15 */
    {0x36220000u, PROTO_UNKNOWN, 0},
    {0x362e0000u, PROTO_AWS, 17}, /* 54.46.0.0/17 */
    {0x362e8000u, PROTO_UNKNOWN, 0},
    {0x36360000u, PROTO_AWS, 15}, /* 54.54.0.0/15 */
    {0x36380000u, PROTO_UNKNOWN, 0},
    {0x36400000u, PROTO_AWS, 11}, /* 54.64.0.0/11 */
    {0x36600000u, PROTO_UNKNOWN, 0},
    {0x36660000u, PROTO_AWS, 16}, /* 54.102.0.0/16 */
    {0x36670000u, PROTO_UNKNOWN, 0},
    {0x36700000u, PROTO_AWS, 18}, /* 54.112.0.0/18 */
    {0x36704000u, PROTO_UNKNOWN, 0},
    {0x36730000u, PROTO_AWS, 16}, /* 54.115.0.0/16 */
    {0x36740000u, PROTO_AWS, 15}, /* 54.116.0.0/15 */
    {0x36760000u, PROTO_UNKNOWN, 0},
    {0x36880000u, PROTO_AWS, 15}, /* 54.136.0.0/15 */
    {0x368a0000u, PROTO_UNKNOWN, 0},
    {0x36900000u, PROTO_AWS, 12}, /* 54.144.0.0/12 */
    {0x36b00000u, PROTO_AWS, 14}, /* 54.176.0.0/14 */
    {0x36b40000u, PROTO_AWS, 15}, /* 54.180.0.0/15 */
    {0x36b60000u, PROTO_CLOUDFRONT, 16}, /* 54.182.0.0/16 */
    {0x36b70000u, PROTO_AWS, 16}, /* 54.183.0.0/16 */
    {0x36b80000u, PROTO_AWS, 13}, /* 54.184.0.0/13 */
    {0x36c00000u, PROTO_CLOUDFRONT, 16}, /* 54.192.0.0/16 */
    {0x36c10000u, PROTO_AWS, 16}, /* 54.193.0.0/16 */
    {0x36c20000u, PROTO_AWS, 15}, /* 54.194.0.0/15 */
    {0x36c40000u, PROTO_AWS, 14}, /* 54.196.0.0/14 */
    {0x36c80000u, PROTO_AWS, 13}, /* 54.200.0.0/13 */
    {0x36d80000u, PROTO_AWS, 14}, /* 54.216.0.0/14 */
    {0x36dc0000u, PROTO_AWS, 15}, /* 54.220.0.0/15 */
    {0x36de0000u, PROTO_AWS, 19}, /* 54.222.0.0/19 */
    {0x36de2000u, PROTO_AWS, 21}, /* 54.222.32.0/21 */
    {0x36de2800u, PROTO_UNKNOWN, 0},
    {0x36de3000u, PROTO_AWS, 21}, /* 54.222.48.0/21 */
    {0x36de3800u, PROTO_UNKNOWN, 0},
    {0x36de3900u, PROTO_AWS, 24}, /* 54.222.57.0/24 */
    {0x36de3a00u, PROTO_AWS, 28}, /* 54.222.58.0/28 */
    {0x36de3a10u, PROTO_UNKNOWN, 0},
    {0x36de3a20u, PROTO_AWS, 27}, /* 54.222.58.32/27 */
    {0x36de3a40u, PROTO_UNKNOWN, 0},
    {0x36de4000u, PROTO_AWS, 21}, /* 54.222.64.0/21 */
    {0x36de4800u, PROTO_UNKNOWN, 0},
    {0x36de4c00u, PROTO_AWS, 22}, /* 54.222.76.0/22 */
    {0x36de5000u, PROTO_AWS, 20}, /* 54.222.80.0/20 */
    {0x36de6000u, PROTO_AWS, 21}, /* 54.222.96.0/21 */
    {0x36de6800u, PROTO_UNKNOWN, 0},
    {0x36de7000u, PROTO_AWS, 20}, /* 54.222.112.0/20 */
    {0x36de8000u, PROTO_AWS, 17}, /* 54.222.128.0/17 */
    {0x36df0000u, PROTO_AWS, 16}, /* 54.223.0.0/16 */
    {0x36e00000u, PROTO_AWS, 14}, /* 54.224.0.0/14 */
    {0x36e40000u, PROTO_AWS, 15}, /* 54.228.0.0/15 */
    {0x36e60000u, PROTO_CLOUDFRONT, 17}, /* 54.230.0.0/17 */
    {0x36e68000u, PROTO_CLOUDFRONT, 18}, /* 54.230.128.0/18 */
    {0x36e6c000u, PROTO_AWS, 21}, /* 54.230.192.0/21 */
    {0x36e6c800u, PROTO_CLOUDFRONT, 21}, /* 54.230.200.0/21 */
    {0x36e6d000u, PROTO_CLOUDFRONT, 20}, /* 54.230.208.0/20 */
    {0x36e6e000u, PROTO_CLOUDFRONT, 19}, /* 54.230.224.0/19 */
    {0x36e70000u, PROTO_AWS, 16}, /* 54.231.0.0/16 */
    {0x36e90000u, PROTO_AWS, 17}, /* 54.233.0.0/17 */
    {0x36e98000u, PROTO_AWS, 18}, /* 54.233.128.0/18 */
    {0x36e9c000u, PROTO_AWS, 19}, /* 54.233.192.0/19 */
    {0x36e9e000u, PROTO_AWS, 20}, /* 54.233.224.0/20 */
    {0x36e9f000u, PROTO_AWS, 21}, /* 54.233.240.0/21 */
    {0x36e9f800u, PROTO_AWS, 22}, /* 54.233.248.0/22 */
    {0x36e9fc00u, PROTO_AWS, 23}, /* 54.233.252.0/23 */
    {0x36e9fe00u, PROTO_AWS, 24}, /* 54.233.254.0/24 */
    {0x36e9ff00u, PROTO_AWS, 25}, /* 54.233.255.0/25 */
    {0x36e9ff80u, PROTO_CLOUDFRONT, 26}, /* 54.233.255.128/26 */
    {0x36e9ffc0u, PROTO_AWS, 26}, /* 54.233.255.192/26 */
    {0x36ea0000u, PROTO_AWS, 15}, /* 54.234.0.0/15 */
    {0x36ee0000u, PROTO_AWS, 16}, /* 54.238.0.0/16 */
    {0x36ef0000u, PROTO_AWS, 19}, /* 54.239.0.0/19 */
    {0x36ef2000u, PROTO_AWS, 21}, /* 54.239.32.0/21 */
    {0x36ef2800u, PROTO_UNKNOWN, 0},
    {0x36ef2880u, PROTO_AWS, 31}, /* 54.239.40.128/31 */
    {0x36ef2882u, PROTO_UNKNOWN, 0},
    {0x36ef2884u, PROTO_AWS, 31}, /* 54.239.40.132/31 */
    {0x36ef2886u, PROTO_AWS, 32}, /* 54.239.40.134/32 */
    {0x36ef2887u, PROTO_UNKNOWN, 0},
    {0x36ef2898u, PROTO_AWS, 29}, /* 54.239.40.152/29 */
    {0x36ef28a0u, PROTO_UNKNOWN, 0},
    {0x36ef3000u, PROTO_AWS, 20}, /* 54.239.48.0/20 */
    {0x36ef4000u, PROTO_AWS, 21}, /* 54.239.64.0/21 */
    {0x36ef4800u, PROTO_UNKNOWN, 0},
    {0x36ef6000u, PROTO_AWS, 24}, /* 54.239.96.0/24 */
    {0x36ef6100u, PROTO_UNKNOWN, 0},
    {0x36ef6200u, PROTO_AWS, 23}, /* 54.239.98.0/23 */
    {0x36ef6600u, PROTO_AWS, 24}, /* 54.239.102.0/24 */
    {0x36ef6700u, PROTO_AWS, 25}, /* 54.239.103.0/25 */
    {0x36ef6780u, PROTO_AWS, 26}, /* 54.239.103.128/26 */
    {0x36ef67c0u, PROTO_UNKNOWN, 0},
    {0x36ef6800u, PROTO_AWS, 21}, /* 54.239.104.0/21 */
    {0x36ef7000u, PROTO_AWS, 23}, /* 54.239.112.0/23 */
    {0x36ef7200u, PROTO_AWS, 25}, /* 54.239.114.0/25 */
    {0x36ef7280u, PROTO_AWS, 26}, /* 54.239.114.128/26 */
    {0x36ef72c0u, PROTO_UNKNOWN, 0},
    {0x36ef7300u, PROTO_AWS, 25}, /* 54.239.115.0/25 */
    {0x36ef7380u, PROTO_UNKNOWN, 0},
    {0x36ef7400u, PROTO_AWS, 22}, /* 54.239.116.0/22 */
    {0x36ef7800u, PROTO_AWS, 21}, /* 54.239.120.0/21 */
    {0x36ef8000u, PROTO_CLOUDFRONT, 18}, /* 54.239.128.0/18 */
    {0x36efc000u, PROTO_CLOUDFRONT, 19}, /* 54.239.192.0/19 */
    {0x36efe000u, PROTO_UNKNOWN, 0},
    {0x36f08000u, PROTO_CLOUDFRONT, 18}, /* 54.240.128.0/18 */
    {0x36f0c000u, PROTO_AWS, 21}, /* 54.240.192.0/21 */
    {0x36f0c800u, PROTO_AWS, 24}, /* 54.240.200.0/24 */
    {0x36f0c900u, PROTO_UNKNOWN, 0},
    {0x36f0ca00u, PROTO_AWS, 23}, /* 54.240.202.0/23 */
    {0x36f0cc00u, PROTO_AWS, 22}, /* 54.240.204.0/22 */
    {0x36f0d000u, PROTO_AWS, 20}, /* 54.240.208.0/20 */
    {0x36f0e000u, PROTO_UNKNOWN, 0},
    {0x36f0e100u, PROTO_AWS, 24}, /* 54.240.225.0/24 */
    {0x36f0e200u, PROTO_AWS, 23}, /* 54.240.226.0/23 */
    {0x36f0e400u, PROTO_AWS, 22}, /* 54.240.228.0/22 */
    {0x36f0ec00u, PROTO_UNKNOWN, 0},
    {0x36f0ec01u, PROTO_AWS, 32}, /* 54.240.236.1/32 */
    {0x36f0ec03u, PROTO_UNKNOWN, 0},
    {0x36f0ec05u, PROTO_AWS, 32}, /* 54.240.236.5/32 */
    {0x36f0ec07u, PROTO_UNKNOWN, 0},
    {0x36f0ec09u, PROTO_AWS, 32}, /* 54.240.236.9/32 */
    {0x36f0ec0bu, PROTO_UNKNOWN, 0},
    {0x36f0ec0du, PROTO_AWS, 32}, /* 54.240.236.13/32 */
    {0x36f0ec0fu, PROTO_UNKNOWN, 0},
    {0x36f0ec11u, PROTO_AWS, 32}, /* 54.240.236.17/32 */
    {0x36f0ec13u, PROTO_UNKNOWN, 0},
    {0x36f0ec15u, PROTO_AWS, 32}, /* 54.240.236.21/32 */
    {0x36f0ec17u, PROTO_UNKNOWN, 0},
    {0x36f0ec19u, PROTO_AWS, 32}, /* 54.240.236.25/32 */
    {0x36f0ec1bu, PROTO_UNKNOWN, 0},
    {0x36f0ec1du, PROTO_AWS, 32}, /* 54.240.236.29/32 */
    {0x36f0ec1fu, PROTO_UNKNOWN, 0},
    {0x36f0ec21u, PROTO_AWS, 32}, /* 54.240.236.33/32 */
    {0x36f0ec23u, PROTO_UNKNOWN, 0},
    {0x36f0ec25u, PROTO_AWS, 32}, /* 54.240.236.37/32 */
    {0x36f0ec27u, PROTO_UNKNOWN, 0},
    {0x36f0ec29u, PROTO_AWS, 32}, /* 54.240.236.41/32 */
    {0x36f0ec2bu, PROTO_UNKNOWN, 0},
    {0x36f0ec2du, PROTO_AWS, 32}, /* 54.240.236.45/32 */
    {0x36f0ec2fu, PROTO_UNKNOWN, 0},
    {0x36f0ec31u, PROTO_AWS, 32}, /* 54.240.236.49/32 */
    {0x36f0ec33u, PROTO_UNKNOWN, 0},
    {0x36f0ec35u, PROTO_AWS, 32}, /* 54.240.236.53/32 */
    {0x36f0ec37u, PROTO_UNKNOWN, 0},
    {0x36f0ec39u, PROTO_AWS, 32}, /* 54.240.236.57/32 */
    {0x36f0ec3bu, PROTO_UNKNOWN, 0},
    {0x36f0ec3du, PROTO_AWS, 32}, /* 54.240.236.61/32 */
    {0x36f0ec3fu, PROTO_UNKNOWN, 0},
    {0x36f0ec41u, PROTO_AWS, 32}, /* 54.240.236.65/32 */
    {0x36f0ec43u, PROTO_UNKNOWN, 0},
    {0x36f0ec45u, PROTO_AWS, 32}, /* 54.240.236.69/32 */
    {0x36f0ec47u, PROTO_UNKNOWN, 0},
    {0x36f0ec49u, PROTO_AWS, 32}, /* 54.240.236.73/32 */
    {0x36f0ec4bu, PROTO_UNKNOWN, 0},
    {0x36f0ec4du, PROTO_AWS, 32}, /* 54.240.236.77/32 */
    {0x36f0ec4fu, PROTO_UNKNOWN, 0},
    {0x36f0ec51u, PROTO_AWS, 32}, /* 54.240.236.81/32 */
    {0x36f0ec53u, PROTO_UNKNOWN, 0},
    {0x36f0ec55u, PROTO_AWS, 32}, /* 54.240.236.85/32 */
    {0x36f0ec57u, PROTO_UNKNOWN, 0},
    {0x36f0ec59u, PROTO_AWS, 32}, /* 54.240.236.89/32 */
    {0x36f0ec5bu, PROTO_UNKNOWN, 0},
    {0x36f0ec5du, PROTO_AWS, 32}, /* 54.240.236.93/32 */
    {0x36f0ec5fu, PROTO_UNKNOWN, 0},
    {0x36f0f100u, PROTO_AWS, 24}, /* 54.240.241.0/24 */
    {0x36f0f200u, PROTO_AWS, 23}, /* 54.240.242.0/23 */
    {0x36f0f400u, PROTO_AWS, 22}, /* 54.240.244.0/22 */
    {0x36f0f800u, PROTO_AWS, 21}, /* 54.240.248.0/21 */
    {0x36f10000u, PROTO_AWS, 16}, /* 54.241.0.0/16 */
    {0x36f20000u, PROTO_AWS, 15}, /* 54.242.0.0/15 */
    {0x36f40000u, PROTO_AWS, 14}, /* 54.244.0.0/14 */
    {0x36f80000u, PROTO_AWS, 13}, /* 54.248.0.0/13 */
    {0x37000000u, PROTO_UNKNOWN, 0},
    {0x38010000u, PROTO_AWS, 16}, /* 56.1.0.0/16 */
    {0x38020000u, PROTO_UNKNOWN, 0},
    {0x38050000u, PROTO_AWS, 16}, /* 56.5.0.0/16 */
    {0x38070000u, PROTO_UNKNOWN, 0},
    {0x38080000u, PROTO_AWS, 16}, /* 56.8.0.0/16 */
    {0x38090000u, PROTO_UNKNOWN, 0},
    {0x380a0000u, PROTO_AWS, 15}, /* 56.10.0.0/15 */
    {0x380c0000u, PROTO_UNKNOWN, 0},
    {0x382f0000u, PROTO_AWS, 16}, /* 56.47.0.0/16 */
    {0x38300000u, PROTO_AWS, 13}, /* 56.48.0.0/13 */
    {0x38380000u, PROTO_AWS, 16}, /* 56.56.0.0/16 */
    {0x38390000u, PROTO_UNKNOWN, 0},
    {0x383d0000u, PROTO_AWS, 16}, /* 56.61.0.0/16 */
    {0x383f0000u, PROTO_UNKNOWN, 0},
    {0x38440000u, PROTO_AWS, 17}, /* 56.68.0.0/17 */
    {0x38448000u, PROTO_UNKNOWN, 0},
    {0x38450000u, PROTO_AWS, 16}, /* 56.69.0.0/16 */
    {0x38460000u, PROTO_AWS, 15}, /* 56.70.0.0/15 */
    {0x38480000u, PROTO_UNKNOWN, 0},
    {0x38600000u, PROTO_AWS, 14}, /* 56.96.0.0/14 */
    {0x38640000u, PROTO_UNKNOWN, 0},
    {0x38700000u, PROTO_AWS, 14}, /* 56.112.0.0/14 */
    {0x38740000u, PROTO_UNKNOWN, 0},
    {0x387c0000u, PROTO_AWS, 16}, /* 56.124.0.0/16 */
    {0x387d0000u, PROTO_AWS, 19}, /* 56.125.0.0/19 */
    {0x387d2000u, PROTO_AWS, 21}, /* 56.125.32.0/21 */
    {0x387d2800u, PROTO_AWS, 22}, /* 56.125.40.0/22 */
    {0x387d2c00u, PROTO_AWS, 23}, /* 56.125.44.0/23 */
    {0x387d2e00u, PROTO_CLOUDFRONT, 24}, /* 56.125.46.0/24 */
    {0x387d2f00u, PROTO_CLOUDFRONT, 32}, /* 56.125.47.0/32 */
    {0x387d2f01u, PROTO_AWS, 32}, /* 56.125.47.1/32 */
    {0x387d2f02u, PROTO_AWS, 31}, /* 56.125.47.2/31 */
    {0x387d2f04u, PROTO_AWS, 30}, /* 56.125.47.4/30 */
    {0x387d2f08u, PROTO_AWS, 29}, /* 56.125.47.8/29 */
    {0x387d2f10u, PROTO_AWS, 28}, /* 56.125.47.16/28 */
    {0x387d2f20u, PROTO_AWS, 27}, /* 56.125.47.32/27 */
    {0x387d2f40u, PROTO_AWS, 26}, /* 56.125.47.64/26 */
    {0x387d2f80u, PROTO_AWS, 25}, /* 56.125.47.128/25 */
    {0x387d3000u, PROTO_CLOUDFRONT, 24}, /* 56.125.48.0/24 */
    {0x387d3100u, PROTO_AWS, 24}, /* 56.125.49.0/24 */
    {0x387d3200u, PROTO_AWS, 23}, /* 56.125.50.0/23 */
    {0x387d3400u, PROTO_AWS, 22}, /* 56.125.52.0/22 */
    {0x387d3800u, PROTO_AWS, 21}, /* 56.125.56.0/21 */
    {0x387d4000u, PROTO_AWS, 18}, /* 56.125.64.0/18 */
    {0x387d8000u, PROTO_AWS, 17}, /* 56.125.128.0/17 */
    {0x387e0000u, PROTO_AWS, 15}, /* 56.126.0.0/15 */
    {0x38800000u, PROTO_AWS, 14}, /* 56.128.0.0/14 */
    {0x38840000u, PROTO_UNKNOWN, 0},
    {0x38880000u, PROTO_AWS, 14}, /* 56.136.0.0/14 */
    {0x388c0000u, PROTO_UNKNOWN, 0},
    {0x389b0000u, PROTO_AWS, 16}, /* 56.155.0.0/16 */
    {0x389c0000u, PROTO_AWS, 15}, /* 56.156.0.0/15 */
    {0x389e0000u, PROTO_UNKNOWN, 0},
    {0x389f0000u, PROTO_AWS, 16}, /* 56.159.0.0/16 */
    {0x38a00000u, PROTO_UNKNOWN, 0},
    {0x38a20000u, PROTO_AWS, 16}, /* 56.162.0.0/16 */
    {0x38a30000u, PROTO_UNKNOWN, 0},
    {0x38a40000u, PROTO_AWS, 16}, /* 56.164.0.0/16 */
    {0x38a50000u, PROTO_UNKNOWN, 0},
    {0x38b80000u, PROTO_AWS, 14}, /* 56.184.0.0/14 */
    {0x38bc0000u, PROTO_UNKNOWN, 0},
    {0x38e40000u, PROTO_AWS, 14}, /* 56.228.0.0/14 */
    {0x38e80000u, PROTO_UNKNOWN, 0},
    {0x38f00000u, PROTO_AWS, 13}, /* 56.240.0.0/13 */
    {0x38f80000u, PROTO_UNKNOWN, 0},
    {0x39960000u, PROTO_AZURE, 15}, /* 57.150.0.0/15 */
    {0x39980000u, PROTO_AZURE, 13}, /* 57.152.0.0/13 */
    {0x39a00000u, PROTO_AZURE, 12}, /* 57.160.0.0/12 */
    {0x39b00000u, PROTO_UNKNOWN, 0},
    {0x39b40000u, PROTO_AWS, 15}, /* 57.180.0.0/15 */
    {0x39b60000u, PROTO_AWS, 17}, /* 57.182.0.0/17 */
    {0x39b68000u, PROTO_AWS, 18}, /* 57.182.128.0/18 */
    {0x39b6c000u, PROTO_AWS, 19}, /* 57.182.192.0/19 */
    {0x39b6e000u, PROTO_AWS, 20}, /* 57.182.224.0/20 */
    {0x39b6f000u, PROTO_AWS, 21}, /* 57.182.240.0/21 */
    {0x39b6f800u, PROTO_AWS, 22}, /* 57.182.248.0/22 */
    {0x39b6fc00u, PROTO_AWS, 24}, /* 57.182.252.0/24 */
    {0x39b6fd00u, PROTO_CLOUDFRONT, 24}, /* 57.182.253.0/24 */
    {0x39b6fe00u, PROTO_AWS, 23}, /* 57.182.254.0/23 */
    {0x39b70000u, PROTO_AWS, 19}, /* 57.183.0.0/19 */
    {0x39b72000u, PROTO_AWS, 21}, /* 57.183.32.0/21 */
    {0x39b72800u, PROTO_AWS, 23}, /* 57.183.40.0/23 */
    {0x39b72a00u, PROTO_CLOUDFRONT, 25}, /* 57.183.42.0/25 */
    {0x39b72a80u, PROTO_AWS, 25}, /* 57.183.42.128/25 */
    {0x39b72b00u, PROTO_AWS, 24}, /* 57.183.43.0/24 */
    {0x39b72c00u, PROTO_AWS, 22}, /* 57.183.44.0/22 */
    {0x39b73000u, PROTO_AWS, 20}, /* 57.183.48.0/20 */
    {0x39b74000u, PROTO_AWS, 18}, /* 57.183.64.0/18 */
    {0x39b78000u, PROTO_AWS, 17}, /* 57.183.128.0/17 */
    {0x39b80000u, PROTO_UNKNOWN, 0},
    {0x3afe8a00u, PROTO_CLOUDFRONT, 25}, /* 58.254.138.0/25 */
    {0x3afe8a80u, PROTO_CLOUDFRONT, 26}, /* 58.254.138.128/26 */
    {0x3afe8ac0u, PROTO_UNKNOWN, 0},
    {0x3d73e000u, PROTO_YAHOO, 20}, /* 61.115.224.0/20 */
    {0x3d73e400u, PROTO_YAHOO, 24}, /* 61.115.228.0/24 */
    {0x3d73e500u, PROTO_YAHOO, 20}, /* 61.115.224.0/20 */
    {0x3d73ea00u, PROTO_YAHOO, 24}, /* 61.115.234.0/24 */
    {0x3d73eb00u, PROTO_YAHOO, 20}, /* 61.115.224.0/20 */
    {0x3d73ee00u, PROTO_YAHOO, 24}, /* 61.115.238.0/24 */
    {0x3d73ef00u, PROTO_YAHOO, 20}, /* 61.115.224.0/20 */
    {0x3d73f000u, PROTO_UNKNOWN, 0},
    {0x3d79c000u, PROTO_YAHOO, 20}, /* 61.121.192.0/20 */
    {0x3d79c400u, PROTO_YAHOO, 22}, /* 61.121.196.0/22 */
    {0x3d79c600u, PROTO_YAHOO, 24}, /* 61.121.198.0/24 */
    {0x3d79c700u, PROTO_YAHOO, 22}, /* 61.121.196.0/22 */
    {0x3d79d000u, PROTO_UNKNOWN, 0},
    {0x3d79f000u, PROTO_YAHOO, 20}, /* 61.121.240.0/20 */
    {0x3d7a0000u, PROTO_UNKNOWN, 0},
    {0x3dc3a000u, PROTO_YAHOO, 23}, /* 61.195.160.0/23 */
    {0x3dc3a200u, PROTO_UNKNOWN, 0},
    {0x3dcbb000u, PROTO_YAHOO, 20}, /* 61.203.176.0/20 */
    {0x3dcbb800u, PROTO_YAHOO, 21}, /* 61.203.184.0/21 */
    {0x3dcbc000u, PROTO_UNKNOWN, 0},
    {0x3dce2000u, PROTO_YAHOO, 22}, /* 61.206.32.0/22 */
    {0x3dce2400u, PROTO_YAHOO, 24}, /* 61.206.36.0/24 */
    {0x3dce2500u, PROTO_UNKNOWN, 0},
    {0x3dd7d000u, PROTO_YAHOO, 20}, /* 61.215.208.0/20 */
    {0x3dd7d400u, PROTO_YAHOO, 22}, /* 61.215.212.0/22 */
    {0x3dd7e000u, PROTO_UNKNOWN, 0},
    {0x3dfb6280u, PROTO_KAKAO, 25}, /* 61.251.98.128/25 */
    {0x3dfb6300u, PROTO_UNKNOWN, 0},
    {0x3e6dc000u, PROTO_WEBEX, 18}, /* 62.109.192.0/18 */
    {0x3e6dc100u, PROTO_WEBEX, 24}, /* 62.109.193.0/24 */
    {0x3e6dc800u, PROTO_WEBEX, 23}, /* 62.109.200.0/23 */
    {0x3e6dc900u, PROTO_WEBEX, 24}, /* 62.109.201.0/24 */
    {0x3e6e0000u, PROTO_UNKNOWN, 0},
    {0x3f200000u, PROTO_AWS, 14}, /* 63.32.0.0/14 */
    {0x3f240000u, PROTO_UNKNOWN, 0},
    {0x3fa36600u, PROTO_YAHOO, 24}, /* 63.163.102.0/24 */
    {0x3fa36700u, PROTO_UNKNOWN, 0},
    {0x3fb00000u, PROTO_AWS, 12}, /* 63.176.0.0/12 */
    {0x3fc00000u, PROTO_UNKNOWN, 0},
    {0x3ff67000u, PROTO_AWS, 22}, /* 63.246.112.0/22 */
    {0x3ff67400u, PROTO_UNKNOWN, 0},
    {0x3ff67700u, PROTO_AWS, 24}, /* 63.246.119.0/24 */
    {0x3ff67800u, PROTO_AWS, 21}, /* 63.246.120.0/21 */
    {0x3ff68000u, PROTO_UNKNOWN, 0},
    {0x3ff98000u, PROTO_AWS, 18}, /* 63.249.128.0/18 */
    {0x3ff9c000u, PROTO_AWS, 19}, /* 63.249.192.0/19 */
    {0x3ff9e000u, PROTO_UNKNOWN, 0},
    {0x3ffac000u, PROTO_YAHOO, 19}, /* 63.250.192.0/19 */
    {0x3ffac400u, PROTO_YAHOO, 22}, /* 63.250.196.0/22 */
    {0x3ffad000u, PROTO_YAHOO, 20}, /* 63.250.208.0/20 */
    {0x3ffae000u, PROTO_UNKNOWN, 0},
    {0x40040800u, PROTO_AZURE, 24}, /* 64.4.8.0/24 */
    {0x40040900u, PROTO_UNKNOWN, 0},
    {0x40043600u, PROTO_AZURE, 24}, /* 64.4.54.0/24 */
    {0x40043700u, PROTO_UNKNOWN, 0},
    {0x4007c800u, PROTO_AWS, 21}, /* 64.7.200.0/21 */
    {0x4007d000u, PROTO_UNKNOWN, 0},
    {0x400f7000u, PROTO_GOOGLE, 20}, /* 64.15.112.0/20 */
    {0x400f8000u, PROTO_UNKNOWN, 0},
    {0x40170000u, PROTO_AWS, 18}, /* 64.23.0.0/18 */
    {0x40174000u, PROTO_UNKNOWN, 0},
    {0x40254000u, PROTO_AWS, 18}, /* 64.37.64.0/18 */
    {0x40258000u, PROTO_UNKNOWN, 0},
    {0x4038a000u, PROTO_YAHOO, 19}, /* 64.56.160.0/19 */
    {0x4038b000u, PROTO_YAHOO, 20}, /* 64.56.176.0/20 */
    {0x4038c000u, PROTO_UNKNOWN, 0},
    {0x403a4c00u, PROTO_YAHOO, 22}, /* 64.58.76.0/22 */
    {0x403a5000u, PROTO_UNKNOWN, 0},
    {0x40428000u, PROTO_AWS, 22}, /* 64.66.128.0/22 */
    {0x40428400u, PROTO_UNKNOWN, 0},
    {0x40428500u, PROTO_AWS, 24}, /* 64.66.133.0/24 */
    {0x40428600u, PROTO_AWS, 23}, /* 64.66.134.0/23 */
    {0x40428800u, PROTO_AWS, 21}, /* 64.66.136.0/21 */
    {0x40429000u, PROTO_AWS, 20}, /* 64.66.144.0/20 */
    {0x4042a000u, PROTO_AWS, 22}, /* 64.66.160.0/22 */
    {0x4042a400u, PROTO_AWS, 24}, /* 64.66.164.0/24 */
    {0x4042a500u, PROTO_UNKNOWN, 0},
    {0x40446000u, PROTO_WEBEX, 21}, /* 64.68.96.0/21 */
    {0x40446100u, PROTO_WEBEX, 24}, /* 64.68.97.0/24 */
    {0x40446200u, PROTO_WEBEX, 23}, /* 64.68.98.0/23 */
    {0x40446300u, PROTO_WEBEX, 24}, /* 64.68.99.0/24 */
    {0x40446800u, PROTO_WEBEX, 21}, /* 64.68.104.0/21 */
    {0x40446900u, PROTO_WEBEX, 24}, /* 64.68.105.0/24 */
    {0x40447800u, PROTO_WEBEX, 21}, /* 64.68.120.0/21 */
    {0x40447900u, PROTO_WEBEX, 24}, /* 64.68.121.0/24 */
    {0x40448000u, PROTO_UNKNOWN, 0},
    {0x4049c000u, PROTO_AWS, 19}, /* 64.73.192.0/19 */
    {0x4049e000u, PROTO_UNKNOWN, 0},
    {0x405bc000u, PROTO_AWS, 19}, /* 64.91.192.0/19 */
    {0x405be000u, PROTO_UNKNOWN, 0},
    {0x4071c000u, PROTO_AWS, 22}, /* 64.113.192.0/22 */
    {0x4071c400u, PROTO_UNKNOWN, 0},
    {0x4071df00u, PROTO_AWS, 24}, /* 64.113.223.0/24 */
    {0x4071e000u, PROTO_UNKNOWN, 0},
    {0x40788000u, PROTO_NETFLIX, 17}, /* 64.120.128.0/17 */
    {0x40790000u, PROTO_UNKNOWN, 0},
    {0x409cd700u, PROTO_YAHOO, 24}, /* 64.156.215.0/24 */
    {0x409cd800u, PROTO_UNKNOWN, 0},
    {0x409d0400u, PROTO_YAHOO, 24}, /* 64.157.4.0/24 */
    {0x409d0500u, PROTO_UNKNOWN, 0},
    {0x40bb8000u, PROTO_AWS, 20}, /* 64.187.128.0/20 */
    {0x40bb9000u, PROTO_UNKNOWN, 0},
    {0x40d1e800u, PROTO_YAHOO, 24}, /* 64.209.232.0/24 */
    {0x40d1e900u, PROTO_UNKNOWN, 0},
    {0x40e80000u, PROTO_AWS, 16}, /* 64.232.0.0/16 */
    {0x40e90000u, PROTO_UNKNOWN, 0},
    {0x40e9a000u, PROTO_GOOGLE, 19}, /* 64.233.160.0/19 */
    {0x40e9c000u, PROTO_UNKNOWN, 0},
    {0x40ec0000u, PROTO_AZURE, 16}, /* 64.236.0.0/16 */
    {0x40ed0000u, PROTO_UNKNOWN, 0},
    {0x40fc4000u, PROTO_CLOUDFRONT, 18}, /* 64.252.64.0/18 */
    {0x40fcc000u, PROTO_UNKNOWN, 0},
    {0x41000000u, PROTO_AWS, 14}, /* 65.0.0.0/14 */
    {0x41040000u, PROTO_AWS, 16}, /* 65.4.0.0/16 */
    {0x41050000u, PROTO_UNKNOWN, 0},
    {0x41080000u, PROTO_CLOUDFRONT, 16}, /* 65.8.0.0/16 */
    {0x41090000u, PROTO_CLOUDFRONT, 17}, /* 65.9.0.0/17 */
    {0x41098000u, PROTO_CLOUDFRONT, 18}, /* 65.9.128.0/18 */
    {0x4109c000u, PROTO_UNKNOWN, 0},
    {0x4132d400u, PROTO_APPLE, 22}, /* 65.50.212.0/22 */
    {0x4132d800u, PROTO_UNKNOWN, 0},
    {0x41340000u, PROTO_AZURE, 19}, /* 65.52.0.0/19 */
    {0x41342000u, PROTO_AZURE, 21}, /* 65.52.32.0/21 */
    {0x41342800u, PROTO_UNKNOWN, 0},
    {0x41343000u, PROTO_AZURE, 20}, /* 65.52.48.0/20 */
    {0x41345000u, PROTO_UNKNOWN, 0},
    {0x41346800u, PROTO_AZURE, 24}, /* 65.52.104.0/24 */
    {0x41346900u, PROTO_UNKNOWN, 0},
    {0x41346a00u, PROTO_AZURE, 24}, /* 65.52.106.0/24 */
    {0x41346b00u, PROTO_UNKNOWN, 0},
    {0x41346c00u, PROTO_AZURE, 22}, /* 65.52.108.0/22 */
    {0x41347000u, PROTO_AZURE, 20}, /* 65.52.112.0/20 */
    {0x41348000u, PROTO_AZURE, 17}, /* 65.52.128.0/17 */
    {0x41350000u, PROTO_UNKNOWN, 0},
    {0x41361380u, PROTO_AZURE, 27}, /* 65.54.19.128/27 */
    {0x413613a0u, PROTO_UNKNOWN, 0},
    {0x41372080u, PROTO_AZURE, 28}, /* 65.55.32.128/28 */
    {0x41372090u, PROTO_UNKNOWN, 0},
    {0x413720c1u, PROTO_AZURE, 32}, /* 65.55.32.193/32 */
    {0x413720c2u, PROTO_AZURE, 31}, /* 65.55.32.194/31 */
    {0x413720c4u, PROTO_AZURE, 32}, /* 65.55.32.196/32 */
    {0x413720c5u, PROTO_UNKNOWN, 0},
    {0x413720d1u, PROTO_AZURE, 32}, /* 65.55.32.209/32 */
    {0x413720d2u, PROTO_AZURE, 31}, /* 65.55.32.210/31 */
    {0x413720d4u, PROTO_UNKNOWN, 0},
    {0x41372c00u, PROTO_AZURE, 25}, /* 65.55.44.0/25 */
    {0x41372c80u, PROTO_AZURE, 27}, /* 65.55.44.128/27 */
    {0x41372ca0u, PROTO_UNKNOWN, 0},
    {0x41373300u, PROTO_AZURE, 24}, /* 65.55.51.0/24 */
    {0x41373400u, PROTO_UNKNOWN, 0},
    {0x41373cb0u, PROTO_AZURE, 28}, /* 65.55.60.176/28 */
    {0x41373cc0u, PROTO_UNKNOWN, 0},
    {0x41376900u, PROTO_AZURE, 26}, /* 65.55.105.0/26 */
    {0x41376940u, PROTO_UNKNOWN, 0},
    {0x41376960u, PROTO_AZURE, 27}, /* 65.55.105.96/27 */
    {0x41376980u, PROTO_UNKNOWN, 0},
    {0x413769a0u, PROTO_AZURE, 27}, /* 65.55.105.160/27 */
    {0x413769c0u, PROTO_AZURE, 26}, /* 65.55.105.192/26 */
    {0x41376a40u, PROTO_AZURE, 27}, /* 65.55.106.64/27 */
    {0x41376a60u, PROTO_UNKNOWN, 0},
    {0x41376a80u, PROTO_AZURE, 25}, /* 65.55.106.128/25 */
    {0x41376b00u, PROTO_AZURE, 28}, /* 65.55.107.0/28 */
    {0x41376b10u, PROTO_UNKNOWN, 0},
    {0x41376b30u, PROTO_AZURE, 28}, /* 65.55.107.48/28 */
    {0x41376b40u, PROTO_AZURE, 26}, /* 65.55.107.64/26 */
    {0x41376b80u, PROTO_UNKNOWN, 0},
    {0x41376c00u, PROTO_AZURE, 23}, /* 65.55.108.0/23 */
    {0x41376e00u, PROTO_AZURE, 24}, /* 65.55.110.0/24 */
    {0x41376f00u, PROTO_UNKNOWN, 0},
    {0x41377800u, PROTO_AZURE, 24}, /* 65.55.120.0/24 */
    {0x41377900u, PROTO_UNKNOWN, 0},
    {0x41379000u, PROTO_AZURE, 23}, /* 65.55.144.0/23 */
    {0x41379200u, PROTO_AZURE, 24}, /* 65.55.146.0/24 */
    {0x41379300u, PROTO_UNKNOWN, 0},
    {0x4137cf00u, PROTO_AZURE, 24}, /* 65.55.207.0/24 */
    {0x4137d000u, PROTO_UNKNOWN, 0},
    {0x4137d100u, PROTO_AZURE, 24}, /* 65.55.209.0/24 */
    {0x4137d300u, PROTO_AZURE, 26}, /* 65.55.211.0/26 */
    {0x4137d340u, PROTO_UNKNOWN, 0},
    {0x4137d400u, PROTO_AZURE, 27}, /* 65.55.212.0/27 */
    {0x4137d420u, PROTO_UNKNOWN, 0},
    {0x4137d480u, PROTO_AZURE, 25}, /* 65.55.212.128/25 */
    {0x4137d500u, PROTO_AZURE, 27}, /* 65.55.213.0/27 */
    {0x4137d520u, PROTO_UNKNOWN, 0},
    {0x4137d540u, PROTO_AZURE, 26}, /* 65.55.213.64/26 */
    {0x4137d5c0u, PROTO_UNKNOWN, 0},
    {0x4137d900u, PROTO_AZURE, 24}, /* 65.55.217.0/24 */
    {0x4137da00u, PROTO_AZURE, 23}, /* 65.55.218.0/23 */
    {0x4137dc00u, PROTO_UNKNOWN, 0},
    {0x4137fa00u, PROTO_AZURE, 24}, /* 65.55.250.0/24 */
    {0x4137fb00u, PROTO_UNKNOWN, 0},
    {0x4137fc00u, PROTO_AZURE, 24}, /* 65.55.252.0/24 */
    {0x4137fd00u, PROTO_UNKNOWN, 0},
    {0x41b00000u, PROTO_AWS, 14}, /* 65.176.0.0/14 */
    {0x41b40000u, PROTO_UNKNOWN, 0},
    {0x42062000u, PROTO_YAHOO, 23}, /* 66.6.32.0/23 */
    {0x42062200u, PROTO_UNKNOWN, 0},
    {0x42070000u, PROTO_AWS, 21}, /* 66.7.0.0/21 */
    {0x42070800u, PROTO_UNKNOWN, 0},
    {0x42240000u, PROTO_AWS, 21}, /* 66.36.0.0/21 */
    {0x42240800u, PROTO_AWS, 23}, /* 66.36.8.0/23 */
    {0x42240a00u, PROTO_AWS, 24}, /* 66.36.10.0/24 */
    {0x42240b00u, PROTO_UNKNOWN, 0},
    {0x422f0000u, PROTO_AWS, 16}, /* 66.47.0.0/16 */
    {0x42300000u, PROTO_UNKNOWN, 0},
    {0x425ee000u, PROTO_YAHOO, 20}, /* 66.94.224.0/20 */
    {0x425ef000u, PROTO_UNKNOWN, 0},
    {0x42660000u, PROTO_GOOGLE, 20}, /* 66.102.0.0/20 */
    {0x42661000u, PROTO_UNKNOWN, 0},
    {0x4272a000u, PROTO_WEBEX, 20}, /* 66.114.160.0/20 */
    {0x4272a100u, PROTO_WEBEX, 24}, /* 66.114.161.0/24 */
    {0x4272a800u, PROTO_WEBEX, 21}, /* 66.114.168.0/21 */
    {0x4272a900u, PROTO_WEBEX, 24}, /* 66.114.169.0/24 */
    {0x4272b000u, PROTO_UNKNOWN, 0},
    {0x42a32000u, PROTO_WEBEX, 20}, /* 66.163.32.0/20 */
    {0x42a32100u, PROTO_WEBEX, 24}, /* 66.163.33.0/24 */
    {0x42a34000u, PROTO_UNKNOWN, 0},
    {0x42a3a000u, PROTO_YAHOO, 20}, /* 66.163.160.0/20 */
    {0x42a3a200u, PROTO_YAHOO, 23}, /* 66.163.162.0/23 */
    {0x42a3a400u, PROTO_YAHOO, 20}, /* 66.163.160.0/20 */
    {0x42a3b000u, PROTO_UNKNOWN, 0},
    {0x42b66000u, PROTO_AWS, 20}, /* 66.182.96.0/20 */
    {0x42b67000u, PROTO_UNKNOWN, 0},
    {0x42c44000u, PROTO_YAHOO, 21}, /* 66.196.64.0/21 */
    {0x42c44600u, PROTO_YAHOO, 23}, /* 66.196.70.0/23 */
    {0x42c44800u, PROTO_UNKNOWN, 0},
    {0x42c45000u, PROTO_YAHOO, 21}, /* 66.196.80.0/21 */
    {0x42c45800u, PROTO_YAHOO, 22}, /* 66.196.88.0/22 */
    {0x42c45c00u, PROTO_UNKNOWN, 0},
    {0x42c46000u, PROTO_YAHOO, 23}, /* 66.196.96.0/23 */
    {0x42c46200u, PROTO_UNKNOWN, 0},
    {0x42c47000u, PROTO_YAHOO, 21}, /* 66.196.112.0/21 */
    {0x42c48000u, PROTO_UNKNOWN, 0},
    {0x42c58000u, PROTO_NETFLIX, 17}, /* 66.197.128.0/17 */
    {0x42c60000u, PROTO_UNKNOWN, 0},
    {0x42da4000u, PROTO_YAHOO, 20}, /* 66.218.64.0/20 */
    {0x42da4800u, PROTO_YAHOO, 22}, /* 66.218.72.0/22 */
    {0x42da4c00u, PROTO_YAHOO, 20}, /* 66.218.64.0/20 */
    {0x42da5000u, PROTO_UNKNOWN, 0},
    {0x42da5c00u, PROTO_YAHOO, 22}, /* 66.218.92.0/22 */
    {0x42da6000u, PROTO_UNKNOWN, 0},
    {0x42dc9000u, PROTO_FACEBOOK, 20}, /* 66.220.144.0/20 */
    {0x42dc9800u, PROTO_FACEBOOK, 21}, /* 66.220.152.0/21 */
    {0x42dc9f00u, PROTO_FACEBOOK, 24}, /* 66.220.159.0/24 */
    {0x42dca000u, PROTO_UNKNOWN, 0},
    {0x42e4a000u, PROTO_YAHOO, 20}, /* 66.228.160.0/20 */
    {0x42e4b000u, PROTO_UNKNOWN, 0},
    {0x42f94000u, PROTO_GOOGLE, 19}, /* 66.249.64.0/19 */
    {0x42f96000u, PROTO_UNKNOWN, 0},
    {0x431c7000u, PROTO_YAHOO, 22}, /* 67.28.112.0/22 */
    {0x431c7400u, PROTO_UNKNOWN, 0},
    {0x43c30000u, PROTO_YAHOO, 17}, /* 67.195.0.0/17 */
    {0x43c38000u, PROTO_UNKNOWN, 0},
    {0x43c39000u, PROTO_YAHOO, 21}, /* 67.195.144.0/21 */
    {0x43c39800u, PROTO_UNKNOWN, 0},
    {0x43c3c000u, PROTO_YAHOO, 22}, /* 67.195.192.0/22 */
    {0x43c3c400u, PROTO_UNKNOWN, 0},
    {0x43c3e000u, PROTO_YAHOO, 22}, /* 67.195.224.0/22 */
    {0x43c3e400u, PROTO_UNKNOWN, 0},
    {0x43c3ec00u, PROTO_YAHOO, 22}, /* 67.195.236.0/22 */
    {0x43c3f000u, PROTO_UNKNOWN, 0},
    {0x43c3fc00u, PROTO_YAHOO, 22}, /* 67.195.252.0/22 */
    {0x43c40000u, PROTO_UNKNOWN, 0},
    {0x43ca0000u, PROTO_AWS, 18}, /* 67.202.0.0/18 */
    {0x43ca4000u, PROTO_UNKNOWN, 0},
    {0x43dce000u, PROTO_AWS, 19}, /* 67.220.224.0/19 */
    {0x43dd0000u, PROTO_UNKNOWN, 0},
    {0x44427000u, PROTO_AWS, 20}, /* 68.66.112.0/20 */
    {0x44428000u, PROTO_UNKNOWN, 0},
    {0x444f0000u, PROTO_AWS, 18}, /* 68.79.0.0/18 */
    {0x444f4000u, PROTO_UNKNOWN, 0},
    {0x448ee000u, PROTO_YAHOO, 21}, /* 68.142.224.0/21 */
    {0x448ee800u, PROTO_YAHOO, 22}, /* 68.142.232.0/22 */
    {0x448ef000u, PROTO_YAHOO, 21}, /* 68.142.240.0/21 */
    {0x448ef800u, PROTO_YAHOO, 24}, /* 68.142.248.0/24 */
    {0x448ef900u, PROTO_UNKNOWN, 0},
    {0x448efc00u, PROTO_YAHOO, 24}, /* 68.142.252.0/24 */
    {0x448f0000u, PROTO_UNKNOWN, 0},
    {0x449a0000u, PROTO_AZURE, 15}, /* 68.154.0.0/15 */
    {0x449c0000u, PROTO_UNKNOWN, 0},
    {0x44b48000u, PROTO_YAHOO, 20}, /* 68.180.128.0/20 */
    {0x44b48100u, PROTO_YAHOO, 24}, /* 68.180.129.0/24 */
    {0x44b48400u, PROTO_YAHOO, 20}, /* 68.180.128.0/20 */
    {0x44b48500u, PROTO_YAHOO, 24}, /* 68.180.133.0/24 */
    {0x44b48600u, PROTO_YAHOO, 20}, /* 68.180.128.0/20 */
    {0x44b48700u, PROTO_YAHOO, 24}, /* 68.180.135.0/24 */
    {0x44b48800u, PROTO_YAHOO, 20}, /* 68.180.128.0/20 */
    {0x44b48900u, PROTO_YAHOO, 24}, /* 68.180.137.0/24 */
    {0x44b48a00u, PROTO_YAHOO, 20}, /* 68.180.128.0/20 */
    {0x44b49000u, PROTO_UNKNOWN, 0},
    {0x44b4a000u, PROTO_YAHOO, 24}, /* 68.180.160.0/24 */
    {0x44b4a100u, PROTO_UNKNOWN, 0},
    {0x44b4c000u, PROTO_YAHOO, 19}, /* 68.180.192.0/19 */
    {0x44b4e000u, PROTO_YAHOO, 20}, /* 68.180.224.0/20 */
    {0x44b50000u, PROTO_UNKNOWN, 0},
    {0x44d20000u, PROTO_AZURE, 15}, /* 68.210.0.0/15 */
    {0x44d40000u, PROTO_UNKNOWN, 0},
    {0x44da0000u, PROTO_AZURE, 15}, /* 68.218.0.0/15 */
    {0x44de0000u, PROTO_UNKNOWN, 0},
    {0x45008800u, PROTO_AWS, 22}, /* 69.0.136.0/22 */
    {0x45008c00u, PROTO_UNKNOWN, 0},
    {0x450c3800u, PROTO_TWITTER, 21}, /* 69.12.56.0/21 */
    {0x450c4000u, PROTO_UNKNOWN, 0},
    {0x45336100u, PROTO_APPLE, 24}, /* 69.51.97.0/24 */
    {0x45336200u, PROTO_UNKNOWN, 0},
    {0x4535e000u, PROTO_NETFLIX, 19}, /* 69.53.224.0/19 */
    {0x4535e300u, PROTO_NETFLIX, 24}, /* 69.53.227.0/24 */
    {0x4535e600u, PROTO_NETFLIX, 19}, /* 69.53.224.0/19 */
    {0x4535f200u, PROTO_NETFLIX, 24}, /* 69.53.242.0/24 */
    {0x4535f300u, PROTO_NETFLIX, 19}, /* 69.53.224.0/19 */
    {0x4535fa00u, PROTO_NETFLIX, 24}, /* 69.53.250.0/24 */
    {0x4535fb00u, PROTO_NETFLIX, 19}, /* 69.53.224.0/19 */
    {0x4535fd00u, PROTO_NETFLIX, 24}, /* 69.53.253.0/24 */
    {0x4535ff00u, PROTO_NETFLIX, 19}, /* 69.53.224.0/19 */
    {0x45360000u, PROTO_UNKNOWN, 0},
    {0x453fb000u, PROTO_FACEBOOK, 20}, /* 69.63.176.0/20 */
    {0x453fb200u, PROTO_FACEBOOK, 24}, /* 69.63.178.0/24 */
    {0x453fb300u, PROTO_FACEBOOK, 20}, /* 69.63.176.0/20 */
    {0x453fb800u, PROTO_FACEBOOK, 21}, /* 69.63.184.0/21 */
    {0x453fba00u, PROTO_FACEBOOK, 24}, /* 69.63.186.0/24 */
    {0x453fbb00u, PROTO_FACEBOOK, 21}, /* 69.63.184.0/21 */
    {0x453fc000u, PROTO_UNKNOWN, 0},
    {0x456b03b0u, PROTO_AWS, 28}, /* 69.107.3.176/28 */
    {0x456b03c0u, PROTO_UNKNOWN, 0},
    {0x456b0670u, PROTO_AWS, 28}, /* 69.107.6.112/28 */
    {0x456b0680u, PROTO_UNKNOWN, 0},
    {0x456b06a0u, PROTO_AWS, 28}, /* 69.107.6.160/28 */
    {0x456b06b0u, PROTO_UNKNOWN, 0},
    {0x456b06c8u, PROTO_AWS, 29}, /* 69.107.6.200/29 */
    {0x456b06d0u, PROTO_AWS, 28}, /* 69.107.6.208/28 */
    {0x456b06e0u, PROTO_AWS, 29}, /* 69.107.6.224/29 */
    {0x456b06e8u, PROTO_UNKNOWN, 0},
    {0x456b0700u, PROTO_AWS, 28}, /* 69.107.7.0/28 */
    {0x456b0710u, PROTO_AWS, 29}, /* 69.107.7.16/29 */
    {0x456b0718u, PROTO_UNKNOWN, 0},
    {0x456b0720u, PROTO_AWS, 27}, /* 69.107.7.32/27 */
    {0x456b0740u, PROTO_AWS, 26}, /* 69.107.7.64/26 */
    {0x456b0780u, PROTO_AWS, 28}, /* 69.107.7.128/28 */
    {0x456b0790u, PROTO_UNKNOWN, 0},
    {0x456b0980u, PROTO_AWS, 28}, /* 69.107.9.128/28 */
    {0x456b0990u, PROTO_UNKNOWN, 0},
    {0x456b09b0u, PROTO_AWS, 28}, /* 69.107.9.176/28 */
    {0x456b09c0u, PROTO_AWS, 26}, /* 69.107.9.192/26 */
    {0x456b0a00u, PROTO_AWS, 23}, /* 69.107.10.0/23 */
    {0x456b0c00u, PROTO_AWS, 24}, /* 69.107.12.0/24 */
    {0x456b0d00u, PROTO_AWS, 25}, /* 69.107.13.0/25 */
    {0x456b0d80u, PROTO_AWS, 28}, /* 69.107.13.128/28 */
    {0x456b0d90u, PROTO_UNKNOWN, 0},
    {0x45915400u, PROTO_APPLE, 23}, /* 69.145.84.0/23 */
    {0x45915600u, PROTO_UNKNOWN, 0},
    {0x45934000u, PROTO_YAHOO, 20}, /* 69.147.64.0/20 */
    {0x45934400u, PROTO_YAHOO, 24}, /* 69.147.68.0/24 */
    {0x45934600u, PROTO_YAHOO, 23}, /* 69.147.70.0/23 */
    {0x45934800u, PROTO_YAHOO, 21}, /* 69.147.72.0/21 */
    {0x45935000u, PROTO_YAHOO, 23}, /* 69.147.80.0/23 */
    {0x45935200u, PROTO_UNKNOWN, 0},
    {0x45935400u, PROTO_YAHOO, 24}, /* 69.147.84.0/24 */
    {0x45935500u, PROTO_UNKNOWN, 0},
    {0x45935800u, PROTO_YAHOO, 22}, /* 69.147.88.0/22 */
    {0x45935a00u, PROTO_YAHOO, 23}, /* 69.147.90.0/23 */
    {0x45935c00u, PROTO_UNKNOWN, 0},
    {0x45936000u, PROTO_YAHOO, 21}, /* 69.147.96.0/21 */
    {0x45936800u, PROTO_UNKNOWN, 0},
    {0x45937000u, PROTO_YAHOO, 23}, /* 69.147.112.0/23 */
    {0x45937200u, PROTO_UNKNOWN, 0},
    {0x45937400u, PROTO_YAHOO, 23}, /* 69.147.116.0/23 */
    {0x45937600u, PROTO_UNKNOWN, 0},
    {0x45937800u, PROTO_YAHOO, 21}, /* 69.147.120.0/21 */
    {0x45938000u, PROTO_UNKNOWN, 0},
    {0x45abe000u, PROTO_FACEBOOK, 19}, /* 69.171.224.0/19 */
    {0x45abef00u, PROTO_FACEBOOK, 24}, /* 69.171.239.0/24 */
    {0x45abf000u, PROTO_FACEBOOK, 20}, /* 69.171.240.0/20 */
    {0x45abfd00u, PROTO_FACEBOOK, 24}, /* 69.171.253.0/24 */
    {0x45abfe00u, PROTO_FACEBOOK, 20}, /* 69.171.240.0/20 */
    {0x45abff00u, PROTO_FACEBOOK, 24}, /* 69.171.255.0/24 */
    {0x45ac0000u, PROTO_UNKNOWN, 0},
    {0x45e6c000u, PROTO_AWS, 18}, /* 69.230.192.0/18 */
    {0x45e70000u, PROTO_UNKNOWN, 0},
    {0x45e78000u, PROTO_AWS, 18}, /* 69.231.128.0/18 */
    {0x45e7c000u, PROTO_UNKNOWN, 0},
    {0x45eac000u, PROTO_AWS, 18}, /* 69.234.192.0/18 */
    {0x45eb0000u, PROTO_UNKNOWN, 0},
    {0x45eb8000u, PROTO_AWS, 18}, /* 69.235.128.0/18 */
    {0x45ebc000u, PROTO_UNKNOWN, 0},
    {0x46208000u, PROTO_GOOGLE, 19}, /* 70.32.128.0/19 */
    {0x4620a000u, PROTO_UNKNOWN, 0},
    {0x46250000u, PROTO_AZURE, 21}, /* 70.37.0.0/21 */
    {0x46250800u, PROTO_AZURE, 22}, /* 70.37.8.0/22 */
    {0x46250c00u, PROTO_AZURE, 32}, /* 70.37.12.0/32 */
    {0x46250c01u, PROTO_UNKNOWN, 0},
    {0x46251000u, PROTO_AZURE, 20}, /* 70.37.16.0/20 */
    {0x46252000u, PROTO_AZURE, 19}, /* 70.37.32.0/19 */
    {0x46254000u, PROTO_AZURE, 18}, /* 70.37.64.0/18 */
    {0x46258000u, PROTO_UNKNOWN, 0},
    {0x46259800u, PROTO_AZURE, 23}, /* 70.37.152.0/23 */
    {0x46259a00u, PROTO_UNKNOWN, 0},
    {0x4625a000u, PROTO_AZURE, 21}, /* 70.37.160.0/21 */
    {0x4625a800u, PROTO_UNKNOWN, 0},
    {0x46840000u, PROTO_CLOUDFRONT, 18}, /* 70.132.0.0/18 */
    {0x46844000u, PROTO_UNKNOWN, 0},
    {0x46980000u, PROTO_AZURE, 15}, /* 70.152.0.0/15 */
    {0x469a0000u, PROTO_UNKNOWN, 0},
    {0x469c0000u, PROTO_AZURE, 15}, /* 70.156.0.0/15 */
    {0x469e0000u, PROTO_UNKNOWN, 0},
    {0x46e0c000u, PROTO_AWS, 18}, /* 70.224.192.0/18 */
    {0x46e10000u, PROTO_UNKNOWN, 0},
    {0x46e84000u, PROTO_AWS, 18}, /* 70.232.64.0/18 */
    {0x46e88000u, PROTO_UNKNOWN, 0},
    {0x4783c000u, PROTO_AWS, 18}, /* 71.131.192.0/18 */
    {0x47844000u, PROTO_UNKNOWN, 0},
    {0x47884000u, PROTO_AWS, 18}, /* 71.136.64.0/18 */
    {0x47888000u, PROTO_UNKNOWN, 0},
    {0x47890000u, PROTO_AWS, 18}, /* 71.137.0.0/18 */
    {0x47894000u, PROTO_UNKNOWN, 0},
    {0x47980000u, PROTO_CLOUDFRONT, 17}, /* 71.152.0.0/17 */
    {0x47988000u, PROTO_UNKNOWN, 0},
    {0x480ec000u, PROTO_GOOGLE, 18}, /* 72.14.192.0/18 */
    {0x480f0000u, PROTO_UNKNOWN, 0},
    {0x4815c000u, PROTO_AWS, 19}, /* 72.21.192.0/19 */
    {0x4815e000u, PROTO_UNKNOWN, 0},
    {0x481e0000u, PROTO_YAHOO, 19}, /* 72.30.0.0/19 */
    {0x481e2000u, PROTO_UNKNOWN, 0},
    {0x481ecc00u, PROTO_YAHOO, 24}, /* 72.30.204.0/24 */
    {0x481ecd00u, PROTO_UNKNOWN, 0},
    {0x481ed000u, PROTO_YAHOO, 22}, /* 72.30.208.0/22 */
    {0x481ed400u, PROTO_UNKNOWN, 0},
    {0x481ee000u, PROTO_YAHOO, 21}, /* 72.30.224.0/21 */
    {0x481ee800u, PROTO_UNKNOWN, 0},
    {0x481ef000u, PROTO_YAHOO, 20}, /* 72.30.240.0/20 */
    {0x481f0000u, PROTO_UNKNOWN, 0},
    {0x48290000u, PROTO_AWS, 20}, /* 72.41.0.0/20 */
    {0x48291000u, PROTO_UNKNOWN, 0},
    {0x482c2000u, PROTO_AWS, 19}, /* 72.44.32.0/19 */
    {0x482c4000u, PROTO_UNKNOWN, 0},
    {0x48900000u, PROTO_AZURE, 14}, /* 72.144.0.0/14 */
    {0x48940000u, PROTO_UNKNOWN, 0},
    {0x48960000u, PROTO_AWS, 20}, /* 72.150.0.0/20 */
    {0x48961000u, PROTO_AWS, 22}, /* 72.150.16.0/22 */
    {0x48961400u, PROTO_AWS, 24}, /* 72.150.20.0/24 */
    {0x48961500u, PROTO_UNKNOWN, 0},
    {0x48980000u, PROTO_AZURE, 14}, /* 72.152.0.0/14 */
    {0x489c0000u, PROTO_UNKNOWN, 0},
    {0x48f20000u, PROTO_AWS, 15}, /* 72.242.0.0/15 */
    {0x48f40000u, PROTO_UNKNOWN, 0},
    {0x4a060400u, PROTO_YAHOO, 22}, /* 74.6.4.0/22 */
    {0x4a060800u, PROTO_UNKNOWN, 0},
    {0x4a062000u, PROTO_YAHOO, 19}, /* 74.6.32.0/19 */
    {0x4a063000u, PROTO_YAHOO, 22}, /* 74.6.48.0/22 */
    {0x4a063400u, PROTO_YAHOO, 19}, /* 74.6.32.0/19 */
    {0x4a068000u, PROTO_UNKNOWN, 0},
    {0x4a069c00u, PROTO_YAHOO, 22}, /* 74.6.156.0/22 */
    {0x4a06a000u, PROTO_YAHOO, 19}, /* 74.6.160.0/19 */
    {0x4a06d000u, PROTO_YAHOO, 20}, /* 74.6.208.0/20 */
    {0x4a06e000u, PROTO_YAHOO, 22}, /* 74.6.224.0/22 */
    {0x4a06e400u, PROTO_UNKNOWN, 0},
    {0x4a06f800u, PROTO_YAHOO, 21}, /* 74.6.248.0/21 */
    {0x4a070000u, PROTO_AZURE, 16}, /* 74.7.0.0/16 */
    {0x4a080000u, PROTO_UNKNOWN, 0},
    {0x4a721800u, PROTO_GOOGLE, 21}, /* 74.114.24.0/21 */
    {0x4a722000u, PROTO_UNKNOWN, 0},
    {0x4a774c00u, PROTO_FACEBOOK, 22}, /* 74.119.76.0/22 */
    {0x4a775000u, PROTO_UNKNOWN, 0},
    {0x4a7d0000u, PROTO_GOOGLE, 16}, /* 74.125.0.0/16 */
    {0x4a7e0000u, PROTO_UNKNOWN, 0},
    {0x4a900000u, PROTO_AZURE, 12}, /* 74.144.0.0/12 */
    {0x4aa00000u, PROTO_AZURE, 14}, /* 74.160.0.0/14 */
    {0x4aa40000u, PROTO_UNKNOWN, 0},
    {0x4ab00000u, PROTO_AZURE, 14}, /* 74.176.0.0/14 */
    {0x4ab40000u, PROTO_UNKNOWN, 0},
    {0x4ae00000u, PROTO_AZURE, 14}, /* 74.224.0.0/14 */
    {0x4ae40000u, PROTO_UNKNOWN, 0},
    {0x4aea0000u, PROTO_AZURE, 15}, /* 74.234.0.0/15 */
    {0x4aec0000u, PROTO_UNKNOWN, 0},
    {0x4af00000u, PROTO_AZURE, 14}, /* 74.240.0.0/14 */
    {0x4af40000u, PROTO_UNKNOWN, 0},
    {0x4af80000u, PROTO_AZURE, 15}, /* 74.248.0.0/15 */
    {0x4afa0000u, PROTO_UNKNOWN, 0},
    {0x4b020000u, PROTO_AWS, 17}, /* 75.2.0.0/17 */
    {0x4b028000u, PROTO_AWS, 18}, /* 75.2.128.0/18 */
    {0x4b02c000u, PROTO_UNKNOWN, 0},
    {0x4b030000u, PROTO_AWS, 18}, /* 75.3.0.0/18 */
    {0x4b034000u, PROTO_UNKNOWN, 0},
    {0x4b038000u, PROTO_AWS, 18}, /* 75.3.128.0/18 */
    {0x4b03c000u, PROTO_UNKNOWN, 0},
    {0x4b16c000u, PROTO_AWS, 18}, /* 75.22.192.0/18 */
    {0x4b170000u, PROTO_UNKNOWN, 0},
    {0x4b2d8000u, PROTO_AWS, 18}, /* 75.45.128.0/18 */
    {0x4b2dc000u, PROTO_UNKNOWN, 0},
    {0x4b2f0000u, PROTO_AWS, 18}, /* 75.47.0.0/18 */
    {0x4b2f4000u, PROTO_UNKNOWN, 0},
    {0x4b4f0000u, PROTO_AWS, 16}, /* 75.79.0.0/16 */
    {0x4b500000u, PROTO_UNKNOWN, 0},
    {0x4b658000u, PROTO_AWS, 17}, /* 75.101.128.0/17 */
    {0x4b660000u, PROTO_UNKNOWN, 0},
    {0x4c0d0000u, PROTO_YAHOO, 17}, /* 76.13.0.0/17 */
    {0x4c0d1800u, PROTO_YAHOO, 21}, /* 76.13.24.0/21 */
    {0x4c0d2000u, PROTO_YAHOO, 17}, /* 76.13.0.0/17 */
    {0x4c0d8000u, PROTO_UNKNOWN, 0},
    {0x4ca20000u, PROTO_AWS, 15}, /* 76.162.0.0/15 */
    {0x4ca40000u, PROTO_UNKNOWN, 0},
    {0x4cdf0000u, PROTO_AWS, 17}, /* 76.223.0.0/17 */
    {0x4cdf8000u, PROTO_UNKNOWN, 0},
    {0x4cdfa800u, PROTO_AWS, 23}, /* 76.223.168.0/23 */
    {0x4cdfaa00u, PROTO_AWS, 28}, /* 76.223.170.0/28 */
    {0x4cdfaa10u, PROTO_UNKNOWN, 0},
    {0x4cdfaa20u, PROTO_AWS, 27}, /* 76.223.170.32/27 */
    {0x4cdfaa40u, PROTO_AWS, 26}, /* 76.223.170.64/26 */
    {0x4cdfaa80u, PROTO_AWS, 27}, /* 76.223.170.128/27 */
    {0x4cdfaaa0u, PROTO_UNKNOWN, 0},
    {0x4cdfac00u, PROTO_AWS, 22}, /* 76.223.172.0/22 */
    {0x4cdfb000u, PROTO_UNKNOWN, 0},
    {0x4d700000u, PROTO_AWS, 14}, /* 77.112.0.0/14 */
    {0x4d740000u, PROTO_UNKNOWN, 0},
    {0x4deeb000u, PROTO_YAHOO, 21}, /* 77.238.176.0/21 */
    {0x4deeb400u, PROTO_YAHOO, 23}, /* 77.238.180.0/23 */
    {0x4deeb600u, PROTO_YAHOO, 24}, /* 77.238.182.0/24 */
    {0x4deeb800u, PROTO_YAHOO, 22}, /* 77.238.184.0/22 */
    {0x4deeba00u, PROTO_YAHOO, 23}, /* 77.238.186.0/23 */
    {0x4deebc00u, PROTO_YAHOO, 22}, /* 77.238.188.0/22 */
    {0x4deec000u, PROTO_UNKNOWN, 0},
    {0x4e0c0000u, PROTO_AWS, 14}, /* 78.12.0.0/14 */
    {0x4e100000u, PROTO_UNKNOWN, 0},
    {0x4f7d0000u, PROTO_AWS, 17}, /* 79.125.0.0/17 */
    {0x4f7d8000u, PROTO_UNKNOWN, 0},
    {0x507e0000u, PROTO_AWS, 20}, /* 80.126.0.0/20 */
    {0x507e1000u, PROTO_UNKNOWN, 0},
    {0x5376f000u, PROTO_AWS, 21}, /* 83.118.240.0/21 */
    {0x5376f800u, PROTO_UNKNOWN, 0},
    {0x53778000u, PROTO_AWS, 18}, /* 83.119.128.0/18 */
    {0x5377c000u, PROTO_UNKNOWN, 0},
    {0x53a00000u, PROTO_AWS, 14}, /* 83.160.0.0/14 */
    {0x53a40000u, PROTO_UNKNOWN, 0},
    {0x55d20000u, PROTO_AZURE, 15}, /* 85.210.0.0/15 */
    {0x55d40000u, PROTO_UNKNOWN, 0},
    {0x56700000u, PROTO_AWS, 15}, /* 86.112.0.0/15 */
    {0x56720000u, PROTO_UNKNOWN, 0},
    {0x57ee5000u, PROTO_AWS, 21}, /* 87.238.80.0/21 */
    {0x57ee5800u, PROTO_UNKNOWN, 0},
    {0x57f86000u, PROTO_YAHOO, 21}, /* 87.248.96.0/21 */
    {0x57f86800u, PROTO_YAHOO, 24}, /* 87.248.104.0/24 */
    {0x57f86a00u, PROTO_UNKNOWN, 0},
    {0x57f86c00u, PROTO_YAHOO, 23}, /* 87.248.108.0/23 */
    {0x57f86e00u, PROTO_UNKNOWN, 0},
    {0x57f86f00u, PROTO_YAHOO, 24}, /* 87.248.111.0/24 */
    {0x57f87000u, PROTO_YAHOO, 21}, /* 87.248.112.0/21 */
    {0x57f87100u, PROTO_YAHOO, 24}, /* 87.248.113.0/24 */
    {0x57f87200u, PROTO_YAHOO, 23}, /* 87.248.114.0/23 */
    {0x57f87800u, PROTO_UNKNOWN, 0},
    {0x58680000u, PROTO_AWS, 13}, /* 88.104.0.0/13 */
    {0x58700000u, PROTO_UNKNOWN, 0},
    {0x59300000u, PROTO_AWS, 13}, /* 89.48.0.0/13 */
    {0x59380000u, PROTO_UNKNOWN, 0},
    {0x593c0000u, PROTO_AWS, 15}, /* 89.60.0.0/15 */
    {0x593e0000u, PROTO_UNKNOWN, 0},
    {0x5a620000u, PROTO_FASTLY, 17}, /* 90.98.0.0/17 */
    {0x5a628000u, PROTO_FASTLY, 18}, /* 90.98.128.0/18 */
    {0x5a62c000u, PROTO_UNKNOWN, 0},
    {0x5bbed800u, PROTO_SKYPE, 21}, /* 91.190.216.0/21 */
    {0x5bbeda00u, PROTO_SKYPE, 23}, /* 91.190.218.0/23 */
    {0x5bbedc00u, PROTO_SKYPE, 24}, /* 91.190.220.0/24 */
    {0x5bbedd00u, PROTO_SKYPE, 21}, /* 91.190.216.0/21 */
    {0x5bbee000u, PROTO_UNKNOWN, 0},
    {0x5d4d8000u, PROTO_AWS, 19}, /* 93.77.128.0/19 */
    {0x5d4da000u, PROTO_UNKNOWN, 0},
    {0x5e240000u, PROTO_AWS, 14}, /* 94.36.0.0/14 */
    {0x5e280000u, PROTO_UNKNOWN, 0},
    {0x5ef55800u, PROTO_AZURE, 21}, /* 94.245.88.0/21 */
    {0x5ef56000u, PROTO_UNKNOWN, 0},
    {0x5ef56800u, PROTO_AZURE, 21}, /* 94.245.104.0/21 */
    {0x5ef57000u, PROTO_UNKNOWN, 0},
    {0x5ef57560u, PROTO_AZURE, 27}, /* 94.245.117.96/27 */
    {0x5ef57580u, PROTO_UNKNOWN, 0},
    {0x5ef57600u, PROTO_AZURE, 25}, /* 94.245.118.0/25 */
    {0x5ef57680u, PROTO_UNKNOWN, 0},
    {0x5ef57880u, PROTO_AZURE, 27}, /* 94.245.120.128/27 */
    {0x5ef578a0u, PROTO_UNKNOWN, 0},
    {0x5ef57a00u, PROTO_AZURE, 24}, /* 94.245.122.0/24 */
    {0x5ef57b00u, PROTO_UNKNOWN, 0},
    {0x5ef57b90u, PROTO_AZURE, 28}, /* 94.245.123.144/28 */
    {0x5ef57ba0u, PROTO_UNKNOWN, 0},
    {0x5ef57bb0u, PROTO_AZURE, 28}, /* 94.245.123.176/28 */
    {0x5ef57bc0u, PROTO_UNKNOWN, 0},
    {0x5f280000u, PROTO_AWS, 15}, /* 95.40.0.0/15 */
    {0x5f2a0000u, PROTO_UNKNOWN, 0},
    {0x60000000u, PROTO_AWS, 18}, /* 96.0.0.0/18 */
    {0x60004000u, PROTO_AWS, 19}, /* 96.0.64.0/19 */
    {0x60006000u, PROTO_AWS, 21}, /* 96.0.96.0/21 */
    {0x60006800u, PROTO_AWS, 22}, /* 96.0.104.0/22 */
    {0x60006c00u, PROTO_AWS, 24}, /* 96.0.108.0/24 */
    {0x60006d00u, PROTO_UNKNOWN, 0},
    {0x60006e00u, PROTO_AWS, 23}, /* 96.0.110.0/23 */
    {0x60007000u, PROTO_AWS, 20}, /* 96.0.112.0/20 */
    {0x60008000u, PROTO_AWS, 19}, /* 96.0.128.0/19 */
    {0x6000a000u, PROTO_AWS, 20}, /* 96.0.160.0/20 */
    {0x6000b000u, PROTO_AWS, 21}, /* 96.0.176.0/21 */
    {0x6000b800u, PROTO_AWS, 22}, /* 96.0.184.0/22 */
    {0x6000bc00u, PROTO_UNKNOWN, 0},
    {0x607f0000u, PROTO_AWS, 17}, /* 96.127.0.0/17 */
    {0x607f8000u, PROTO_UNKNOWN, 0},
    {0x62400000u, PROTO_AZURE, 14}, /* 98.64.0.0/14 */
    {0x62440000u, PROTO_UNKNOWN, 0},
    {0x62460000u, PROTO_AZURE, 15}, /* 98.70.0.0/15 */
    {0x62480000u, PROTO_UNKNOWN, 0},
    {0x62500000u, PROTO_AWS, 12}, /* 98.80.0.0/12 */
    {0x62600000u, PROTO_UNKNOWN, 0},
    {0x62820000u, PROTO_AWS, 15}, /* 98.130.0.0/15 */
    {0x62840000u, PROTO_UNKNOWN, 0},
    {0x62880000u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x62886c00u, PROTO_YAHOO, 22}, /* 98.136.108.0/22 */
    {0x62887000u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x62888000u, PROTO_YAHOO, 19}, /* 98.136.128.0/19 */
    {0x6288ac00u, PROTO_YAHOO, 23}, /* 98.136.172.0/23 */
    {0x6288ae00u, PROTO_YAHOO, 19}, /* 98.136.160.0/19 */
    {0x6288c000u, PROTO_YAHOO, 18}, /* 98.136.192.0/18 */
    {0x6288c800u, PROTO_YAHOO, 21}, /* 98.136.200.0/21 */
    {0x6288d000u, PROTO_YAHOO, 18}, /* 98.136.192.0/18 */
    {0x6288e000u, PROTO_YAHOO, 23}, /* 98.136.224.0/23 */
    {0x6288e200u, PROTO_YAHOO, 18}, /* 98.136.192.0/18 */
    {0x62890000u, PROTO_YAHOO, 19}, /* 98.137.0.0/19 */
    {0x62892000u, PROTO_YAHOO, 22}, /* 98.137.32.0/22 */
    {0x62892400u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x62894000u, PROTO_YAHOO, 20}, /* 98.137.64.0/20 */
    {0x62895000u, PROTO_YAHOO, 21}, /* 98.137.80.0/21 */
    {0x62896000u, PROTO_YAHOO, 19}, /* 98.137.96.0/19 */
    {0x62898000u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x62898a00u, PROTO_YAHOO, 23}, /* 98.137.138.0/23 */
    {0x62898c00u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x6289a000u, PROTO_YAHOO, 19}, /* 98.137.160.0/19 */
    {0x6289c000u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x6289c800u, PROTO_YAHOO, 21}, /* 98.137.200.0/21 */
    {0x6289d000u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x6289e000u, PROTO_YAHOO, 19}, /* 98.137.224.0/19 */
    {0x6289ec00u, PROTO_YAHOO, 24}, /* 98.137.236.0/24 */
    {0x6289ed00u, PROTO_YAHOO, 19}, /* 98.137.224.0/19 */
    {0x628a0000u, PROTO_YAHOO, 17}, /* 98.138.0.0/17 */
    {0x628a8000u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x628b0400u, PROTO_YAHOO, 22}, /* 98.139.4.0/22 */
    {0x628b1000u, PROTO_YAHOO, 21}, /* 98.139.16.0/21 */
    {0x628b2000u, PROTO_YAHOO, 20}, /* 98.139.32.0/20 */
    {0x628b3000u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x628b6000u, PROTO_YAHOO, 21}, /* 98.139.96.0/21 */
    {0x628b6400u, PROTO_YAHOO, 22}, /* 98.139.100.0/22 */
    {0x628b6800u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x628b7000u, PROTO_YAHOO, 21}, /* 98.139.112.0/21 */
    {0x628b7800u, PROTO_YAHOO, 22}, /* 98.139.120.0/22 */
    {0x628b7c00u, PROTO_YAHOO, 14}, /* 98.136.0.0/14 */
    {0x628b8000u, PROTO_YAHOO, 17}, /* 98.139.128.0/17 */
    {0x628c0000u, PROTO_UNKNOWN, 0},
    {0x630a0000u, PROTO_AWS, 18}, /* 99.10.0.0/18 */
    {0x630a4000u, PROTO_UNKNOWN, 0},
    {0x634d0000u, PROTO_AWS, 18}, /* 99.77.0.0/18 */
    {0x634d4000u, PROTO_UNKNOWN, 0},
    {0x634d8000u, PROTO_AWS, 18}, /* 99.77.128.0/18 */
    {0x634dc000u, PROTO_UNKNOWN, 0},
    {0x634de800u, PROTO_AWS, 21}, /* 99.77.232.0/21 */
    {0x634df800u, PROTO_AWS, 22}, /* 99.77.248.0/22 */
    {0x634dfc00u, PROTO_AWS, 23}, /* 99.77.252.0/23 */
    {0x634dfe00u, PROTO_AWS, 24}, /* 99.77.254.0/24 */
    {0x634dff00u, PROTO_UNKNOWN, 0},
    {0x634e8000u, PROTO_AWS, 19}, /* 99.78.128.0/19 */
    {0x634ea000u, PROTO_AWS, 21}, /* 99.78.160.0/21 */
    {0x634ea800u, PROTO_AWS, 22}, /* 99.78.168.0/22 */
    {0x634eac00u, PROTO_AWS, 24}, /* 99.78.172.0/24 */
    {0x634ead00u, PROTO_UNKNOWN, 0},
    {0x634eb000u, PROTO_AWS, 20}, /* 99.78.176.0/20 */
    {0x634ec000u, PROTO_AWS, 21}, /* 99.78.192.0/21 */
    {0x634ec800u, PROTO_UNKNOWN, 0},
    {0x634ed000u, PROTO_AWS, 21}, /* 99.78.208.0/21 */
    {0x634ed800u, PROTO_AWS, 22}, /* 99.78.216.0/22 */
    {0x634edc00u, PROTO_AWS, 26}, /* 99.78.220.0/26 */
    {0x634edc40u, PROTO_UNKNOWN, 0},
    {0x634edc41u, PROTO_AWS, 32}, /* 99.78.220.65/32 */
    {0x634edc43u, PROTO_UNKNOWN, 0},
    {0x634edc80u, PROTO_AWS, 26}, /* 99.78.220.128/26 */
    {0x634edcc0u, PROTO_UNKNOWN, 0},
    {0x634ee400u, PROTO_AWS, 22}, /* 99.78.228.0/22 */
    {0x634ee800u, PROTO_AWS, 21}, /* 99.78.232.0/21 */
    {0x634ef000u, PROTO_AWS, 20}, /* 99.78.240.0/20 */
    {0x634f0000u, PROTO_AWS, 17}, /* 99.79.0.0/17 */
    {0x634f8000u, PROTO_AWS, 19}, /* 99.79.128.0/19 */
    {0x634fa000u, PROTO_AWS, 21}, /* 99.79.160.0/21 */
    {0x634fa800u, PROTO_AWS, 24}, /* 99.79.168.0/24 */
    {0x634fa900u, PROTO_CLOUDFRONT, 24}, /* 99.79.169.0/24 */
    {0x634faa00u, PROTO_AWS, 23}, /* 99.79.170.0/23 */
    {0x634fac00u, PROTO_AWS, 22}, /* 99.79.172.0/22 */
    {0x634fb000u, PROTO_AWS, 20}, /* 99.79.176.0/20 */
    {0x634fc000u, PROTO_AWS, 18}, /* 99.79.192.0/18 */
    {0x63500000u, PROTO_AWS, 15}, /* 99.80.0.0/15 */
    {0x63520000u, PROTO_AWS, 22}, /* 99.82.0.0/22 */
    {0x63520400u, PROTO_UNKNOWN, 0},
    {0x63520800u, PROTO_AWS, 21}, /* 99.82.8.0/21 */
    {0x63521000u, PROTO_UNKNOWN, 0},
    {0x63528000u, PROTO_AWS, 18}, /* 99.82.128.0/18 */
    {0x6352c000u, PROTO_UNKNOWN, 0},
    {0x63534000u, PROTO_AWS, 19}, /* 99.83.64.0/19 */
    {0x63536000u, PROTO_AWS, 21}, /* 99.83.96.0/21 */
    {0x63536800u, PROTO_AWS, 22}, /* 99.83.104.0/22 */
    {0x63536c00u, PROTO_AWS, 23}, /* 99.83.108.0/23 */
    {0x63536e00u, PROTO_UNKNOWN, 0},
    {0x63537000u, PROTO_AWS, 21}, /* 99.83.112.0/21 */
    {0x63537800u, PROTO_AWS, 22}, /* 99.83.120.0/22 */
    {0x63537c00u, PROTO_UNKNOWN, 0},
    {0x63538000u, PROTO_AWS, 17}, /* 99.83.128.0/17 */
    {0x63540000u, PROTO_CLOUDFRONT, 16}, /* 99.84.0.0/16 */
    {0x63550000u, PROTO_UNKNOWN, 0},
    {0x63560000u, PROTO_CLOUDFRONT, 16}, /* 99.86.0.0/16 */
    {0x63570000u, PROTO_AWS, 19}, /* 99.87.0.0/19 */
    {0x63572000u, PROTO_AWS, 22}, /* 99.87.32.0/22 */
    {0x63572400u, PROTO_UNKNOWN, 0},
    {0x63960000u, PROTO_AWS, 17}, /* 99.150.0.0/17 */
    {0x63968000u, PROTO_UNKNOWN, 0},
    {0x63974000u, PROTO_AWS, 18}, /* 99.151.64.0/18 */
    {0x63978000u, PROTO_AWS, 19}, /* 99.151.128.0/19 */
    {0x6397a000u, PROTO_AWS, 20}, /* 99.151.160.0/20 */
    {0x6397b000u, PROTO_UNKNOWN, 0},
    {0x6397b800u, PROTO_AWS, 21}, /* 99.151.184.0/21 */
    {0x6397c000u, PROTO_UNKNOWN, 0},
    {0x63b54000u, PROTO_AWS, 18}, /* 99.181.64.0/18 */
    {0x63b58000u, PROTO_UNKNOWN, 0},
    {0x63c80000u, PROTO_AWS, 13}, /* 99.200.0.0/13 */
    {0x63d00000u, PROTO_UNKNOWN, 0},
    {0x64140000u, PROTO_AWS, 14}, /* 100.20.0.0/14 */
    {0x64180000u, PROTO_AWS, 13}, /* 100.24.0.0/13 */
    {0x64200000u, PROTO_UNKNOWN, 0},
    {0x64300000u, PROTO_AWS, 12}, /* 100.48.0.0/12 */
    {0x64400000u, PROTO_UNKNOWN, 0},
    {0x66250000u, PROTO_AZURE, 16}, /* 102.37.0.0/16 */
    {0x66260000u, PROTO_UNKNOWN, 0},
    {0x66850000u, PROTO_AZURE, 16}, /* 102.133.0.0/16 */
    {0x66860000u, PROTO_UNKNOWN, 0},
    {0x67024800u, PROTO_YAHOO, 22}, /* 103.2.72.0/22 */
    {0x67024c00u, PROTO_UNKNOWN, 0},
    {0x6702f400u, PROTO_YAHOO, 22}, /* 103.2.244.0/22 */
    {0x6702f800u, PROTO_UNKNOWN, 0},
    {0x67040800u, PROTO_AWS, 21}, /* 103.4.8.0/21 */
    {0x67041000u, PROTO_UNKNOWN, 0},
    {0x67042000u, PROTO_YAHOO, 22}, /* 103.4.32.0/22 */
    {0x67042400u, PROTO_UNKNOWN, 0},
    {0x67044400u, PROTO_YAHOO, 22}, /* 103.4.68.0/22 */
    {0x67044800u, PROTO_UNKNOWN, 0},
    {0x67046000u, PROTO_FACEBOOK, 22}, /* 103.4.96.0/22 */
    {0x67046400u, PROTO_UNKNOWN, 0},
    {0x67083000u, PROTO_YAHOO, 22}, /* 103.8.48.0/22 */
    {0x67083400u, PROTO_UNKNOWN, 0},
    {0x6708ac00u, PROTO_AWS, 22}, /* 103.8.172.0/22 */
    {0x6708b000u, PROTO_UNKNOWN, 0},
    {0x670dbc00u, PROTO_AWS, 23}, /* 103.13.188.0/23 */
    {0x670dbe00u, PROTO_UNKNOWN, 0},
    {0x6715f400u, PROTO_CLOUDFLARE, 22}, /* 103.21.244.0/22 */
    {0x6715f800u, PROTO_UNKNOWN, 0},
    {0x6716c800u, PROTO_CLOUDFLARE, 22}, /* 103.22.200.0/22 */
    {0x6716cc00u, PROTO_UNKNOWN, 0},
    {0x67199c00u, PROTO_AZURE, 24}, /* 103.25.156.0/24 */
    {0x67199d00u, PROTO_UNKNOWN, 0},
    {0x671b9400u, PROTO_KAKAO, 24}, /* 103.27.148.0/24 */
    {0x671b9600u, PROTO_UNKNOWN, 0},
    {0x671f0400u, PROTO_CLOUDFLARE, 22}, /* 103.31.4.0/22 */
    {0x671f0800u, PROTO_UNKNOWN, 0},
    {0x67246000u, PROTO_AZURE, 24}, /* 103.36.96.0/24 */
    {0x67246100u, PROTO_UNKNOWN, 0},
    {0x67254000u, PROTO_YAHOO, 22}, /* 103.37.64.0/22 */
    {0x67254400u, PROTO_UNKNOWN, 0},
    {0x67286e00u, PROTO_YAHOO, 23}, /* 103.40.110.0/23 */
    {0x67286f00u, PROTO_YAHOO, 24}, /* 103.40.111.0/24 */
    {0x67287000u, PROTO_UNKNOWN, 0},
    {0x67353000u, PROTO_AWS, 22}, /* 103.53.48.0/22 */
    {0x67353400u, PROTO_UNKNOWN, 0},
    {0x674f6400u, PROTO_APPLE, 24}, /* 103.79.100.0/24 */
    {0x674f6800u, PROTO_UNKNOWN, 0},
    {0x6757cc00u, PROTO_NETFLIX, 22}, /* 103.87.204.0/22 */
    {0x6757d000u, PROTO_UNKNOWN, 0},
    {0x67c68100u, PROTO_APPLE, 24}, /* 103.198.129.0/24 */
    {0x67c68200u, PROTO_UNKNOWN, 0},
    {0x67f18000u, PROTO_YAHOO, 22}, /* 103.241.128.0/22 */
    {0x67f18200u, PROTO_YAHOO, 23}, /* 103.241.130.0/23 */
    {0x67f18400u, PROTO_UNKNOWN, 0},
    {0x67f19800u, PROTO_YAHOO, 24}, /* 103.241.152.0/24 */
    {0x67f19b00u, PROTO_UNKNOWN, 0},
    {0x67f43200u, PROTO_FASTLY, 24}, /* 103.244.50.0/24 */
    {0x67f43300u, PROTO_UNKNOWN, 0},
    {0x67f5de00u, PROTO_FASTLY, 23}, /* 103.245.222.0/23 */
    {0x67f5e000u, PROTO_FASTLY, 24}, /* 103.245.224.0/24 */
    {0x67f5e100u, PROTO_UNKNOWN, 0},
    {0x67f63800u, PROTO_KAKAO, 22}, /* 103.246.56.0/22 */
    {0x67f63900u, PROTO_KAKAO, 24}, /* 103.246.57.0/24 */
    {0x67f63c00u, PROTO_UNKNOWN, 0},
    {0x67f69400u, PROTO_AWS, 22}, /* 103.246.148.0/22 */
    {0x67f69800u, PROTO_UNKNOWN, 0},
    {0x67fc7000u, PROTO_TWITTER, 23}, /* 103.252.112.0/23 */
    {0x67fc7400u, PROTO_UNKNOWN, 0},
    {0x67ff8c00u, PROTO_AZURE, 23}, /* 103.255.140.0/23 */
    {0x67ff8e00u, PROTO_UNKNOWN, 0},
    {0x68100000u, PROTO_CLOUDFLARE, 13}, /* 104.16.0.0/13 */
    {0x68180000u, PROTO_CLOUDFLARE, 14}, /* 104.24.0.0/14 */
    {0x681c0000u, PROTO_UNKNOWN, 0},
    {0x68280000u, PROTO_AZURE, 14}, /* 104.40.0.0/14 */
    {0x682c0000u, PROTO_UNKNOWN, 0},
    {0x682c5800u, PROTO_AZURE, 21}, /* 104.44.88.0/21 */
    {0x682c6000u, PROTO_UNKNOWN, 0},
    {0x682c8000u, PROTO_AZURE, 18}, /* 104.44.128.0/18 */
    {0x682cc000u, PROTO_UNKNOWN, 0},
    {0x682d0000u, PROTO_AZURE, 16}, /* 104.45.0.0/16 */
    {0x682e0000u, PROTO_AZURE, 20}, /* 104.46.0.0/20 */
    {0x682e1000u, PROTO_AZURE, 26}, /* 104.46.16.0/26 */
    {0x682e1040u, PROTO_UNKNOWN, 0},
    {0x682e1800u, PROTO_AZURE, 21}, /* 104.46.24.0/21 */
    {0x682e2000u, PROTO_AZURE, 19}, /* 104.46.32.0/19 */
    {0x682e4000u, PROTO_AZURE, 18}, /* 104.46.64.0/18 */
    {0x682e8000u, PROTO_UNKNOWN, 0},
    {0x682ea000u, PROTO_AZURE, 19}, /* 104.46.160.0/19 */
    {0x682ee000u, PROTO_AZURE, 20}, /* 104.46.224.0/20 */
    {0x682ef000u, PROTO_UNKNOWN, 0},
    {0x682f8000u, PROTO_AZURE, 18}, /* 104.47.128.0/18 */
    {0x682fc000u, PROTO_UNKNOWN, 0},
    {0x682fc800u, PROTO_AZURE, 21}, /* 104.47.200.0/21 */
    {0x682fd800u, PROTO_UNKNOWN, 0},
    {0x682fd840u, PROTO_AZURE, 26}, /* 104.47.216.64/26 */
    {0x682fd880u, PROTO_UNKNOWN, 0},
    {0x682fda00u, PROTO_AZURE, 23}, /* 104.47.218.0/23 */
    {0x682fdc00u, PROTO_AZURE, 22}, /* 104.47.220.0/22 */
    {0x682fe000u, PROTO_AZURE, 20}, /* 104.47.224.0/20 */
    {0x682ff000u, PROTO_UNKNOWN, 0},
    {0x682ff800u, PROTO_AZURE, 21}, /* 104.47.248.0/21 */
    {0x68300000u, PROTO_UNKNOWN, 0},
    {0x68911000u, PROTO_YAHOO, 20}, /* 104.145.16.0/20 */
    {0x68912000u, PROTO_UNKNOWN, 0},
    {0x68997000u, PROTO_AWS, 22}, /* 104.153.112.0/22 */
    {0x68997400u, PROTO_AWS, 24}, /* 104.153.116.0/24 */
    {0x68997500u, PROTO_UNKNOWN, 0},
    {0x68997600u, PROTO_AWS, 24}, /* 104.153.118.0/24 */
    {0x68997700u, PROTO_UNKNOWN, 0},
    {0x689a0000u, PROTO_GOOGLE, 20}, /* 104.154.0.0/20 */
    {0x689a1000u, PROTO_GOOGLE_CLOUD, 20}, /* 104.154.16.0/20 */
    {0x689a2000u, PROTO_GOOGLE_CLOUD, 19}, /* 104.154.32.0/19 */
    {0x689a6000u, PROTO_GOOGLE_CLOUD, 20}, /* 104.154.96.0/20 */
    {0x689a7000u, PROTO_GOOGLE, 24}, /* 104.154.112.0/24 */
    {0x689a7100u, PROTO_GOOGLE_CLOUD, 24}, /* 104.154.113.0/24 */
    {0x689a7200u, PROTO_GOOGLE_CLOUD, 23}, /* 104.154.114.0/23 */
    {0x689a7400u, PROTO_GOOGLE_CLOUD, 22}, /* 104.154.116.0/22 */
    {0x689a7800u, PROTO_GOOGLE_CLOUD, 23}, /* 104.154.120.0/23 */
    {0x689a7a00u, PROTO_GOOGLE, 23}, /* 104.154.122.0/23 */
    {0x689a7c00u, PROTO_GOOGLE, 22}, /* 104.154.124.0/22 */
    {0x689a8000u, PROTO_GOOGLE_CLOUD, 17}, /* 104.154.128.0/17 */
    {0x689b8000u, PROTO_GOOGLE_CLOUD, 18}, /* 104.155.128.0/18 */
    {0x689bc000u, PROTO_GOOGLE_CLOUD, 19}, /* 104.155.192.0/19 */
    {0x689be000u, PROTO_GOOGLE_CLOUD, 20}, /* 104.155.224.0/20 */
    {0x689bf000u, PROTO_GOOGLE, 20}, /* 104.155.240.0/20 */
    {0x689c0000u, PROTO_UNKNOWN, 0},
    {0x689c5000u, PROTO_FASTLY, 20}, /* 104.156.80.0/20 */
    {0x689c6000u, PROTO_UNKNOWN, 0},
    {0x68c40000u, PROTO_GOOGLE_CLOUD, 18}, /* 104.196.0.0/18 */
    {0x68c44000u, PROTO_GOOGLE, 24}, /* 104.196.64.0/24 */
    {0x68c44100u, PROTO_GOOGLE_CLOUD, 24}, /* 104.196.65.0/24 */
    {0x68c44200u, PROTO_GOOGLE_CLOUD, 23}, /* 104.196.66.0/23 */
    {0x68c44400u, PROTO_GOOGLE_CLOUD, 22}, /* 104.196.68.0/22 */
    {0x68c44800u, PROTO_GOOGLE, 21}, /* 104.196.72.0/21 */
    {0x68c45000u, PROTO_GOOGLE, 20}, /* 104.196.80.0/20 */
    {0x68c46000u, PROTO_GOOGLE_CLOUD, 19}, /* 104.196.96.0/19 */
    {0x68c48000u, PROTO_GOOGLE_CLOUD, 17}, /* 104.196.128.0/17 */
    {0x68c50000u, PROTO_GOOGLE_CLOUD, 16}, /* 104.197.0.0/16 */
    {0x68c70000u, PROTO_GOOGLE_CLOUD, 18}, /* 104.199.0.0/18 */
    {0x68c74000u, PROTO_GOOGLE, 23}, /* 104.199.64.0/23 */
    {0x68c74200u, PROTO_GOOGLE_CLOUD, 23}, /* 104.199.66.0/23 */
    {0x68c74400u, PROTO_GOOGLE_CLOUD, 22}, /* 104.199.68.0/22 */
    {0x68c74800u, PROTO_GOOGLE_CLOUD, 21}, /* 104.199.72.0/21 */
    {0x68c75000u, PROTO_GOOGLE_CLOUD, 20}, /* 104.199.80.0/20 */
    {0x68c76000u, PROTO_GOOGLE_CLOUD, 19}, /* 104.199.96.0/19 */
    {0x68c78000u, PROTO_GOOGLE_CLOUD, 18}, /* 104.199.128.0/18 */
    {0x68c7c000u, PROTO_GOOGLE_CLOUD, 19}, /* 104.199.192.0/19 */
    {0x68c7e000u, PROTO_GOOGLE_CLOUD, 20}, /* 104.199.224.0/20 */
    {0x68c7f000u, PROTO_GOOGLE, 23}, /* 104.199.240.0/23 */
    {0x68c7f200u, PROTO_GOOGLE_CLOUD, 23}, /* 104.199.242.0/23 */
    {0x68c7f400u, PROTO_GOOGLE_CLOUD, 22}, /* 104.199.244.0/22 */
    {0x68c7f800u, PROTO_GOOGLE_CLOUD, 21}, /* 104.199.248.0/21 */
    {0x68c80000u, PROTO_UNKNOWN, 0},
    {0x68d00000u, PROTO_AZURE, 16}, /* 104.208.0.0/16 */
    {0x68d10000u, PROTO_AZURE, 18}, /* 104.209.0.0/18 */
    {0x68d14000u, PROTO_AZURE, 19}, /* 104.209.64.0/19 */
    {0x68d16000u, PROTO_UNKNOWN, 0},
    {0x68d18000u, PROTO_AZURE, 17}, /* 104.209.128.0/17 */
    {0x68d20000u, PROTO_AZURE, 20}, /* 104.210.0.0/20 */
    {0x68d21000u, PROTO_UNKNOWN, 0},
    {0x68d22000u, PROTO_AZURE, 19}, /* 104.210.32.0/19 */
    {0x68d24000u, PROTO_AZURE, 18}, /* 104.210.64.0/18 */
    {0x68d28000u, PROTO_AZURE, 19}, /* 104.210.128.0/19 */
    {0x68d2a000u, PROTO_UNKNOWN, 0},
    {0x68d2b000u, PROTO_AZURE, 20}, /* 104.210.176.0/20 */
    {0x68d2c000u, PROTO_AZURE, 19}, /* 104.210.192.0/19 */
    {0x68d2e000u, PROTO_UNKNOWN, 0},
    {0x68d30000u, PROTO_AZURE, 16}, /* 104.211.0.0/16 */
    {0x68d40000u, PROTO_UNKNOWN, 0},
    {0x68d60000u, PROTO_AZURE, 15}, /* 104.214.0.0/15 */
    {0x68d80000u, PROTO_AWS, 15}, /* 104.216.0.0/15 */
    {0x68da0000u, PROTO_UNKNOWN, 0},
    {0x68eda000u, PROTO_GOOGLE, 19}, /* 104.237.160.0/19 */
    {0x68edc000u, PROTO_UNKNOWN, 0},
    {0x68f42800u, PROTO_TWITTER, 24}, /* 104.244.40.0/24 */
    {0x68f43000u, PROTO_UNKNOWN, 0},
    {0x68ff3800u, PROTO_AWS, 32}, /* 104.255.56.0/32 */
    {0x68ff3801u, PROTO_UNKNOWN, 0},
    {0x68ff3803u, PROTO_AWS, 32}, /* 104.255.56.3/32 */
    {0x68ff3804u, PROTO_UNKNOWN, 0},
    {0x68ff380bu, PROTO_AWS, 32}, /* 104.255.56.11/32 */
    {0x68ff380du, PROTO_UNKNOWN, 0},
    {0x68ff380fu, PROTO_AWS, 32}, /* 104.255.56.15/32 */
    {0x68ff3810u, PROTO_AWS, 30}, /* 104.255.56.16/30 */
    {0x68ff3814u, PROTO_AWS, 32}, /* 104.255.56.20/32 */
    {0x68ff3815u, PROTO_UNKNOWN, 0},
    {0x68ff3817u, PROTO_AWS, 32}, /* 104.255.56.23/32 */
    {0x68ff3818u, PROTO_AWS, 30}, /* 104.255.56.24/30 */
    {0x68ff381cu, PROTO_AWS, 31}, /* 104.255.56.28/31 */
    {0x68ff381eu, PROTO_UNKNOWN, 0},
    {0x68ff3831u, PROTO_AWS, 32}, /* 104.255.56.49/32 */
    {0x68ff3832u, PROTO_AWS, 31}, /* 104.255.56.50/31 */
    {0x68ff3834u, PROTO_AWS, 32}, /* 104.255.56.52/32 */
    {0x68ff3835u, PROTO_UNKNOWN, 0},
    {0x68ff3837u, PROTO_AWS, 32}, /* 104.255.56.55/32 */
    {0x68ff3838u, PROTO_AWS, 31}, /* 104.255.56.56/31 */
    {0x68ff383au, PROTO_UNKNOWN, 0},
    {0x68ff383cu, PROTO_AWS, 32}, /* 104.255.56.60/32 */
    {0x68ff383du, PROTO_UNKNOWN, 0},
    {0x68ff383fu, PROTO_AWS, 32}, /* 104.255.56.63/32 */
    {0x68ff3840u, PROTO_AWS, 29}, /* 104.255.56.64/29 */
    {0x68ff3848u, PROTO_AWS, 32}, /* 104.255.56.72/32 */
    {0x68ff3849u, PROTO_UNKNOWN, 0},
    {0x68ff3900u, PROTO_AWS, 32}, /* 104.255.57.0/32 */
    {0x68ff3901u, PROTO_UNKNOWN, 0},
    {0x68ff3929u, PROTO_AWS, 32}, /* 104.255.57.41/32 */
    {0x68ff392au, PROTO_UNKNOWN, 0},
    {0x68ff3962u, PROTO_AWS, 32}, /* 104.255.57.98/32 */
    {0x68ff3963u, PROTO_UNKNOWN, 0},
    {0x68ff3964u, PROTO_AWS, 30}, /* 104.255.57.100/30 */
    {0x68ff3968u, PROTO_UNKNOWN, 0},
    {0x68ff39a4u, PROTO_AWS, 30}, /* 104.255.57.164/30 */
    {0x68ff39a8u, PROTO_AWS, 29}, /* 104.255.57.168/29 */
    {0x68ff39b0u, PROTO_AWS, 30}, /* 104.255.57.176/30 */
    {0x68ff39b4u, PROTO_UNKNOWN, 0},
    {0x68ff39b6u, PROTO_AWS, 31}, /* 104.255.57.182/31 */
    {0x68ff39b8u, PROTO_UNKNOWN, 0},
    {0x68ff3a00u, PROTO_AWS, 32}, /* 104.255.58.0/32 */
    {0x68ff3a01u, PROTO_UNKNOWN, 0},
    {0x68ff3a2bu, PROTO_AWS, 32}, /* 104.255.58.43/32 */
    {0x68ff3a2du, PROTO_UNKNOWN, 0},
    {0x68ff3a3fu, PROTO_AWS, 32}, /* 104.255.58.63/32 */
    {0x68ff3a40u, PROTO_UNKNOWN, 0},
    {0x68ff3a54u, PROTO_AWS, 32}, /* 104.255.58.84/32 */
    {0x68ff3a55u, PROTO_UNKNOWN, 0},
    {0x68ff3a5bu, PROTO_AWS, 32}, /* 104.255.58.91/32 */
    {0x68ff3a5cu, PROTO_UNKNOWN, 0},
    {0x68ff3aecu, PROTO_AWS, 30}, /* 104.255.58.236/30 */
    {0x68ff3af0u, PROTO_UNKNOWN, 0},
    {0x68ff3b51u, PROTO_AWS, 32}, /* 104.255.59.81/32 */
    {0x68ff3b52u, PROTO_AWS, 31}, /* 104.255.59.82/31 */
    {0x68ff3b54u, PROTO_UNKNOWN, 0},
    {0x68ff3b55u, PROTO_AWS, 32}, /* 104.255.59.85/32 */
    {0x68ff3b56u, PROTO_AWS, 31}, /* 104.255.59.86/31 */
    {0x68ff3b58u, PROTO_AWS, 32}, /* 104.255.59.88/32 */
    {0x68ff3b59u, PROTO_UNKNOWN, 0},
    {0x68ff3b5bu, PROTO_AWS, 32}, /* 104.255.59.91/32 */
    {0x68ff3b5cu, PROTO_UNKNOWN, 0},
    {0x68ff3b65u, PROTO_AWS, 32}, /* 104.255.59.101/32 */
    {0x68ff3b66u, PROTO_AWS, 31}, /* 104.255.59.102/31 */
    {0x68ff3b6au, PROTO_AWS, 32}, /* 104.255.59.106/32 */
    {0x68ff3b6bu, PROTO_UNKNOWN, 0},
    {0x68ff3b72u, PROTO_AWS, 31}, /* 104.255.59.114/31 */
    {0x68ff3b74u, PROTO_UNKNOWN, 0},
    {0x68ff3b76u, PROTO_AWS, 31}, /* 104.255.59.118/31 */
    {0x68ff3b78u, PROTO_UNKNOWN, 0},
    {0x68ff3b7au, PROTO_AWS, 31}, /* 104.255.59.122/31 */
    {0x68ff3b7cu, PROTO_AWS, 30}, /* 104.255.59.124/30 */
    {0x68ff3b80u, PROTO_UNKNOWN, 0},
    {0x68ff3b82u, PROTO_AWS, 31}, /* 104.255.59.130/31 */
    {0x68ff3b84u, PROTO_AWS, 30}, /* 104.255.59.132/30 */
    {0x68ff3b8cu, PROTO_UNKNOWN, 0},
    {0x68ff3bc4u, PROTO_AWS, 30}, /* 104.255.59.196/30 */
    {0x68ff3bc8u, PROTO_AWS, 31}, /* 104.255.59.200/31 */
    {0x68ff3bcau, PROTO_UNKNOWN, 0},
    {0x68ff3bceu, PROTO_AWS, 31}, /* 104.255.59.206/31 */
    {0x68ff3bd0u, PROTO_AWS, 29}, /* 104.255.59.208/29 */
    {0x68ff3bd8u, PROTO_AWS, 31}, /* 104.255.59.216/31 */
    {0x68ff3bdau, PROTO_UNKNOWN, 0},
    {0x68ff3beeu, PROTO_AWS, 31}, /* 104.255.59.238/31 */
    {0x68ff3bf0u, PROTO_AWS, 30}, /* 104.255.59.240/30 */
    {0x68ff3bf4u, PROTO_UNKNOWN, 0},
    {0x68ff3d00u, PROTO_AWS, 31}, /* 104.255.61.0/31 */
    {0x68ff3d02u, PROTO_UNKNOWN, 0},
    {0x6b140000u, PROTO_AWS, 14}, /* 107.20.0.0/14 */
    {0x6b180000u, PROTO_UNKNOWN, 0},
    {0x6ba7a000u, PROTO_GOOGLE_CLOUD, 19}, /* 107.167.160.0/19 */
    {0x6ba7c000u, PROTO_UNKNOWN, 0},
    {0x6bb00000u, PROTO_AWS, 15}, /* 107.176.0.0/15 */
    {0x6bb20000u, PROTO_UNKNOWN, 0},
    {0x6bb2c000u, PROTO_GOOGLE, 20}, /* 107.178.192.0/20 */
    {0x6bb2d000u, PROTO_GOOGLE_CLOUD, 20}, /* 107.178.208.0/20 */
    {0x6bb2e000u, PROTO_GOOGLE, 20}, /* 107.178.224.0/20 */
    {0x6bb2f000u, PROTO_GOOGLE_CLOUD, 20}, /* 107.178.240.0/20 */
    {0x6bb30000u, PROTO_UNKNOWN, 0},
    {0x6c3b5000u, PROTO_GOOGLE_CLOUD, 20}, /* 108.59.80.0/20 */
    {0x6c3b6000u, PROTO_UNKNOWN, 0},
    {0x6c800000u, PROTO_AWS, 13}, /* 108.128.0.0/13 */
    {0x6c880000u, PROTO_AWS, 15}, /* 108.136.0.0/15 */
    {0x6c8a0000u, PROTO_CLOUDFRONT, 15}, /* 108.138.0.0/15 */
    {0x6c8c0000u, PROTO_AZURE, 14}, /* 108.140.0.0/14 */
    {0x6c900000u, PROTO_UNKNOWN, 0},
    {0x6c9c0000u, PROTO_CLOUDFRONT, 14}, /* 108.156.0.0/14 */
    {0x6ca00000u, PROTO_UNKNOWN, 0},
    {0x6ca2c000u, PROTO_CLOUDFLARE, 18}, /* 108.162.192.0/18 */
    {0x6ca30000u, PROTO_UNKNOWN, 0},
    {0x6ca6e000u, PROTO_AWS, 19}, /* 108.166.224.0/19 */
    {0x6ca70000u, PROTO_UNKNOWN, 0},
    {0x6caac000u, PROTO_GOOGLE, 18}, /* 108.170.192.0/18 */
    {0x6cab0000u, PROTO_UNKNOWN, 0},
    {0x6caf2000u, PROTO_NETFLIX, 20}, /* 108.175.32.0/20 */
    {0x6caf2f00u, PROTO_NETFLIX, 24}, /* 108.175.47.0/24 */
    {0x6caf3000u, PROTO_AWS, 20}, /* 108.175.48.0/20 */
    {0x6caf4000u, PROTO_UNKNOWN, 0},
    {0x6cb10000u, PROTO_GOOGLE, 17}, /* 108.177.0.0/17 */
    {0x6cb18000u, PROTO_UNKNOWN, 0},
    {0x6e4c8c00u, PROTO_KAKAO, 22}, /* 110.76.140.0/22 */
    {0x6e4c9000u, PROTO_UNKNOWN, 0},
    {0x6eee0200u, PROTO_AWS, 23}, /* 110.238.2.0/23 */
    {0x6eee0400u, PROTO_UNKNOWN, 0},
    {0x6f0dab80u, PROTO_CLOUDFRONT, 25}, /* 111.13.171.128/25 */
    {0x6f0dac00u, PROTO_UNKNOWN, 0},
    {0x6f0db920u, PROTO_CLOUDFRONT, 27}, /* 111.13.185.32/27 */
    {0x6f0db960u, PROTO_UNKNOWN, 0},
    {0x6fdd1c00u, PROTO_AZURE, 22}, /* 111.221.28.0/22 */
    {0x6fdd2000u, PROTO_UNKNOWN, 0},
    {0x6fdd5000u, PROTO_AZURE, 20}, /* 111.221.80.0/20 */
    {0x6fdd7000u, PROTO_UNKNOWN, 0},
    {0x711d8000u, PROTO_KAKAO, 19}, /* 113.29.128.0/19 */
    {0x711d8100u, PROTO_KAKAO, 24}, /* 113.29.129.0/24 */
    {0x711d8400u, PROTO_KAKAO, 19}, /* 113.29.128.0/19 */
    {0x711d9000u, PROTO_KAKAO, 20}, /* 113.29.144.0/20 */
    {0x711da000u, PROTO_KAKAO, 19}, /* 113.29.160.0/19 */
    {0x711db300u, PROTO_KAKAO, 24}, /* 113.29.179.0/24 */
    {0x711db600u, PROTO_KAKAO, 19}, /* 113.29.160.0/19 */
    {0x711db800u, PROTO_KAKAO, 24}, /* 113.29.184.0/24 */
    {0x711dbc00u, PROTO_KAKAO, 19}, /* 113.29.160.0/19 */
    {0x711dbe00u, PROTO_KAKAO, 24}, /* 113.29.190.0/24 */
    {0x711dc000u, PROTO_UNKNOWN, 0},
    {0x713d6a00u, PROTO_KAKAO, 24}, /* 113.61.106.0/24 */
    {0x713d6c00u, PROTO_UNKNOWN, 0},
    {0x721dc000u, PROTO_WEBEX, 19}, /* 114.29.192.0/19 */
    {0x721dc100u, PROTO_WEBEX, 24}, /* 114.29.193.0/24 */
    {0x721dc800u, PROTO_WEBEX, 23}, /* 114.29.200.0/23 */
    {0x721dc900u, PROTO_WEBEX, 24}, /* 114.29.201.0/24 */
    {0x721dca00u, PROTO_WEBEX, 23}, /* 114.29.202.0/23 */
    {0x721dcb00u, PROTO_WEBEX, 24}, /* 114.29.203.0/24 */
    {0x721dcc00u, PROTO_WEBEX, 22}, /* 114.29.204.0/22 */
    {0x721dcd00u, PROTO_WEBEX, 24}, /* 114.29.205.0/24 */
    {0x721dd000u, PROTO_WEBEX, 21}, /* 114.29.208.0/21 */
    {0x721dd100u, PROTO_WEBEX, 24}, /* 114.29.209.0/24 */
    {0x721de000u, PROTO_UNKNOWN, 0},
    {0x726e3000u, PROTO_YAHOO, 20}, /* 114.110.48.0/20 */
    {0x726e4000u, PROTO_UNKNOWN, 0},
    {0x726f4000u, PROTO_YAHOO, 18}, /* 114.111.64.0/18 */
    {0x726f8000u, PROTO_UNKNOWN, 0},
    {0x7481e200u, PROTO_CLOUDFRONT, 25}, /* 116.129.226.0/25 */
    {0x7481e280u, PROTO_CLOUDFRONT, 26}, /* 116.129.226.128/26 */
    {0x7481e2c0u, PROTO_UNKNOWN, 0},
    {0x7568bc00u, PROTO_YAHOO, 24}, /* 117.104.188.0/24 */
    {0x7568be00u, PROTO_UNKNOWN, 0},
    {0x7697e000u, PROTO_YAHOO, 19}, /* 118.151.224.0/19 */
    {0x76980000u, PROTO_UNKNOWN, 0},
    {0x76c16140u, PROTO_CLOUDFRONT, 26}, /* 118.193.97.64/26 */
    {0x76c16180u, PROTO_CLOUDFRONT, 25}, /* 118.193.97.128/25 */
    {0x76c16200u, PROTO_UNKNOWN, 0},
    {0x7793b600u, PROTO_CLOUDFRONT, 25}, /* 119.147.182.0/25 */
    {0x7793b680u, PROTO_CLOUDFRONT, 26}, /* 119.147.182.128/26 */
    {0x7793b6c0u, PROTO_UNKNOWN, 0},
    {0x77a10c00u, PROTO_YAHOO, 24}, /* 119.161.12.0/24 */
    {0x77a10d00u, PROTO_UNKNOWN, 0},
    {0x77a10e00u, PROTO_YAHOO, 23}, /* 119.161.14.0/23 */
    {0x77a11000u, PROTO_UNKNOWN, 0},
    {0x77ebc000u, PROTO_KAKAO, 20}, /* 119.235.192.0/20 */
    {0x77ebd000u, PROTO_UNKNOWN, 0},
    {0x78340c40u, PROTO_CLOUDFRONT, 26}, /* 120.52.12.64/26 */
    {0x78340c80u, PROTO_UNKNOWN, 0},
    {0x78341660u, PROTO_CLOUDFRONT, 27}, /* 120.52.22.96/27 */
    {0x78341680u, PROTO_UNKNOWN, 0},
    {0x78342780u, PROTO_CLOUDFRONT, 27}, /* 120.52.39.128/27 */
    {0x783427a0u, PROTO_UNKNOWN, 0},
    {0x783499c0u, PROTO_CLOUDFRONT, 26}, /* 120.52.153.192/26 */
    {0x78349a00u, PROTO_UNKNOWN, 0},
    {0x78e8ec00u, PROTO_CLOUDFRONT, 25}, /* 120.232.236.0/25 */
    {0x78e8ec80u, PROTO_CLOUDFRONT, 26}, /* 120.232.236.128/26 */
    {0x78e8ecc0u, PROTO_UNKNOWN, 0},
    {0x78fdf0c0u, PROTO_CLOUDFRONT, 26}, /* 120.253.240.192/26 */
    {0x78fdf100u, PROTO_UNKNOWN, 0},
    {0x78fdf1a0u, PROTO_CLOUDFRONT, 27}, /* 120.253.241.160/27 */
    {0x78fdf1c0u, PROTO_UNKNOWN, 0},
    {0x78fdf580u, PROTO_CLOUDFRONT, 26}, /* 120.253.245.128/26 */
    {0x78fdf5c0u, PROTO_CLOUDFRONT, 27}, /* 120.253.245.192/27 */
    {0x78fdf5e0u, PROTO_UNKNOWN, 0},
    {0x795b6200u, PROTO_AWS, 23}, /* 121.91.98.0/23 */
    {0x795b6400u, PROTO_UNKNOWN, 0},
    {0x79643800u, PROTO_YAHOO, 21}, /* 121.100.56.0/21 */
    {0x79644000u, PROTO_UNKNOWN, 0},
    {0x7ac83d00u, PROTO_AWS, 24}, /* 122.200.61.0/24 */
    {0x7ac83e00u, PROTO_UNKNOWN, 0},
    {0x7af8c000u, PROTO_AWS, 18}, /* 122.248.192.0/18 */
    {0x7af90000u, PROTO_UNKNOWN, 0},
    {0x7c538000u, PROTO_YAHOO, 17}, /* 124.83.128.0/17 */
    {0x7c540000u, PROTO_UNKNOWN, 0},
    {0x7c6c4c00u, PROTO_YAHOO, 23}, /* 124.108.76.0/23 */
    {0x7c6c4e00u, PROTO_UNKNOWN, 0},
    {0x7c932000u, PROTO_YAHOO, 19}, /* 124.147.32.0/19 */
    {0x7c934000u, PROTO_UNKNOWN, 0},
    {0x80180000u, PROTO_AZURE, 16}, /* 128.24.0.0/16 */
    {0x80190000u, PROTO_UNKNOWN, 0},
    {0x80550000u, PROTO_AZURE, 16}, /* 128.85.0.0/16 */
    {0x80560000u, PROTO_UNKNOWN, 0},
    {0x80cb0000u, PROTO_AZURE, 16}, /* 128.203.0.0/16 */
    {0x80cc0000u, PROTO_UNKNOWN, 0},
    {0x80fb0000u, PROTO_AZURE, 16}, /* 128.251.0.0/16 */
    {0x80fc0000u, PROTO_UNKNOWN, 0},
    {0x81860000u, PROTO_FACEBOOK, 16}, /* 129.134.0.0/16 */
    {0x81870000u, PROTO_UNKNOWN, 0},
    {0x82210000u, PROTO_AZURE, 16}, /* 130.33.0.0/16 */
    {0x82220000u, PROTO_UNKNOWN, 0},
    {0x826b0000u, PROTO_AZURE, 16}, /* 130.107.0.0/16 */
    {0x826c0000u, PROTO_UNKNOWN, 0},
    {0x82830000u, PROTO_AZURE, 16}, /* 130.131.0.0/16 */
    {0x82840000u, PROTO_UNKNOWN, 0},
    {0x82b00000u, PROTO_CLOUDFRONT, 17}, /* 130.176.0.0/17 */
    {0x82b08000u, PROTO_CLOUDFRONT, 18}, /* 130.176.128.0/18 */
    {0x82b0c000u, PROTO_CLOUDFRONT, 19}, /* 130.176.192.0/19 */
    {0x82b0e000u, PROTO_CLOUDFRONT, 20}, /* 130.176.224.0/20 */
    {0x82b0f000u, PROTO_UNKNOWN, 0},
    {0x82b0fe00u, PROTO_AWS, 23}, /* 130.176.254.0/23 */
    {0x82b10000u, PROTO_UNKNOWN, 0},
    {0x82d30000u, PROTO_GOOGLE, 22}, /* 130.211.0.0/22 */
    {0x82d30400u, PROTO_GOOGLE_CLOUD, 22}, /* 130.211.4.0/22 */
    {0x82d30800u, PROTO_GOOGLE_CLOUD, 21}, /* 130.211.8.0/21 */
    {0x82d31000u, PROTO_GOOGLE_CLOUD, 20}, /* 130.211.16.0/20 */
    {0x82d32000u, PROTO_GOOGLE_CLOUD, 19}, /* 130.211.32.0/19 */
    {0x82d34000u, PROTO_GOOGLE_CLOUD, 18}, /* 130.211.64.0/18 */
    {0x82d38000u, PROTO_GOOGLE_CLOUD, 17}, /* 130.211.128.0/17 */
    {0x82d40000u, PROTO_UNKNOWN, 0},
    {0x82d50000u, PROTO_AZURE, 16}, /* 130.213.0.0/16 */
    {0x82d60000u, PROTO_UNKNOWN, 0},
    {0x83004800u, PROTO_CLOUDFLARE, 22}, /* 131.0.72.0/22 */
    {0x83004c00u, PROTO_UNKNOWN, 0},
    {0x83910000u, PROTO_AZURE, 16}, /* 131.145.0.0/16 */
    {0x83920000u, PROTO_UNKNOWN, 0},
    {0x83a30000u, PROTO_AZURE, 16}, /* 131.163.0.0/16 */
    {0x83a40000u, PROTO_UNKNOWN, 0},
    {0x83bd0000u, PROTO_AZURE, 16}, /* 131.189.0.0/16 */
    {0x83be0000u, PROTO_UNKNOWN, 0},
    {0x83fd0c00u, PROTO_AZURE, 22}, /* 131.253.12.0/22 */
    {0x83fd1000u, PROTO_UNKNOWN, 0},
    {0x83fd1800u, PROTO_AZURE, 28}, /* 131.253.24.0/28 */
    {0x83fd1810u, PROTO_UNKNOWN, 0},
    {0x83fd18a0u, PROTO_AZURE, 27}, /* 131.253.24.160/27 */
    {0x83fd18c0u, PROTO_AZURE, 26}, /* 131.253.24.192/26 */
    {0x83fd1900u, PROTO_AZURE, 24}, /* 131.253.25.0/24 */
    {0x83fd1a00u, PROTO_UNKNOWN, 0},
    {0x83fd1b00u, PROTO_AZURE, 24}, /* 131.253.27.0/24 */
    {0x83fd1c00u, PROTO_UNKNOWN, 0},
    {0x83fd22e0u, PROTO_AZURE, 27}, /* 131.253.34.224/27 */
    {0x83fd2300u, PROTO_UNKNOWN, 0},
    {0x83fd2380u, PROTO_AZURE, 25}, /* 131.253.35.128/25 */
    {0x83fd2400u, PROTO_UNKNOWN, 0},
    {0x83fd2480u, PROTO_AZURE, 26}, /* 131.253.36.128/26 */
    {0x83fd24c0u, PROTO_UNKNOWN, 0},
    {0x83fd24e0u, PROTO_AZURE, 27}, /* 131.253.36.224/27 */
    {0x83fd2500u, PROTO_UNKNOWN, 0},
    {0x83fd2600u, PROTO_AZURE, 26}, /* 131.253.38.0/26 */
    {0x83fd2640u, PROTO_UNKNOWN, 0},
    {0x83fd2680u, PROTO_AZURE, 26}, /* 131.253.38.128/26 */
    {0x83fd26c0u, PROTO_UNKNOWN, 0},
    {0x83fd26e0u, PROTO_AZURE, 27}, /* 131.253.38.224/27 */
    {0x83fd2700u, PROTO_UNKNOWN, 0},
    {0x83fd2800u, PROTO_AZURE, 23}, /* 131.253.40.0/23 */
    {0x83fd2a00u, PROTO_UNKNOWN, 0},
    {0x84a40000u, PROTO_AZURE, 16}, /* 132.164.0.0/16 */
    {0x84a50000u, PROTO_UNKNOWN, 0},
    {0x84c40000u, PROTO_AZURE, 16}, /* 132.196.0.0/16 */
    {0x84c50000u, PROTO_UNKNOWN, 0},
    {0x84dc0000u, PROTO_AZURE, 16}, /* 132.220.0.0/16 */
    {0x84dd0000u, PROTO_UNKNOWN, 0},
    {0x84f5e600u, PROTO_AZURE, 23}, /* 132.245.230.0/23 */
    {0x84f5e800u, PROTO_UNKNOWN, 0},
    {0x86210000u, PROTO_AZURE, 16}, /* 134.33.0.0/16 */
    {0x86220000u, PROTO_UNKNOWN, 0},
    {0x86700000u, PROTO_AZURE, 16}, /* 134.112.0.0/16 */
    {0x86710000u, PROTO_UNKNOWN, 0},
    {0x868a0000u, PROTO_AZURE, 16}, /* 134.138.0.0/16 */
    {0x868b0000u, PROTO_UNKNOWN, 0},
    {0x86950000u, PROTO_AZURE, 16}, /* 134.149.0.0/16 */
    {0x86960000u, PROTO_UNKNOWN, 0},
    {0x86aab000u, PROTO_AZURE, 22}, /* 134.170.176.0/22 */
    {0x86aab400u, PROTO_UNKNOWN, 0},
    {0x86aac000u, PROTO_AZURE, 21}, /* 134.170.192.0/21 */
    {0x86aac800u, PROTO_UNKNOWN, 0},
    {0x86aadc00u, PROTO_AZURE, 22}, /* 134.170.220.0/22 */
    {0x86aae000u, PROTO_UNKNOWN, 0},
    {0x870d0000u, PROTO_AZURE, 16}, /* 135.13.0.0/16 */
    {0x870e0000u, PROTO_UNKNOWN, 0},
    {0x87120000u, PROTO_AZURE, 16}, /* 135.18.0.0/16 */
    {0x87130000u, PROTO_UNKNOWN, 0},
    {0x87740000u, PROTO_AZURE, 16}, /* 135.116.0.0/16 */
    {0x87750000u, PROTO_UNKNOWN, 0},
    {0x87770000u, PROTO_AZURE, 16}, /* 135.119.0.0/16 */
    {0x87780000u, PROTO_UNKNOWN, 0},
    {0x87820000u, PROTO_AZURE, 16}, /* 135.130.0.0/16 */
    {0x87830000u, PROTO_UNKNOWN, 0},
    {0x87950000u, PROTO_AZURE, 16}, /* 135.149.0.0/16 */
    {0x87960000u, PROTO_UNKNOWN, 0},
    {0x87ab0000u, PROTO_AZURE, 16}, /* 135.171.0.0/16 */
    {0x87ac0000u, PROTO_UNKNOWN, 0},
    {0x87dc0000u, PROTO_AZURE, 16}, /* 135.220.0.0/16 */
    {0x87dd0000u, PROTO_UNKNOWN, 0},
    {0x87de0000u, PROTO_AZURE, 16}, /* 135.222.0.0/16 */
    {0x87df0000u, PROTO_UNKNOWN, 0},
    {0x87e00000u, PROTO_AZURE, 15}, /* 135.224.0.0/15 */
    {0x87e20000u, PROTO_UNKNOWN, 0},
    {0x87e80000u, PROTO_AZURE, 14}, /* 135.232.0.0/14 */
    {0x87ec0000u, PROTO_AZURE, 15}, /* 135.236.0.0/15 */
    {0x87ee0000u, PROTO_UNKNOWN, 0},
    {0x88080000u, PROTO_AWS, 15}, /* 136.8.0.0/15 */
    {0x880a0000u, PROTO_UNKNOWN, 0},
    {0x88120000u, PROTO_AWS, 21}, /* 136.18.0.0/21 */
    {0x88120800u, PROTO_UNKNOWN, 0},
    {0x88121200u, PROTO_AWS, 23}, /* 136.18.18.0/23 */
    {0x88121400u, PROTO_AWS, 22}, /* 136.18.20.0/22 */
    {0x88121800u, PROTO_UNKNOWN, 0},
    {0x88122000u, PROTO_AWS, 23}, /* 136.18.32.0/23 */
    {0x88122200u, PROTO_AWS, 24}, /* 136.18.34.0/24 */
    {0x88122300u, PROTO_UNKNOWN, 0},
    {0x88123800u, PROTO_AWS, 21}, /* 136.18.56.0/21 */
    {0x88124000u, PROTO_UNKNOWN, 0},
    {0x88128000u, PROTO_AWS, 19}, /* 136.18.128.0/19 */
    {0x8812a000u, PROTO_AWS, 22}, /* 136.18.160.0/22 */
    {0x8812a400u, PROTO_AWS, 23}, /* 136.18.164.0/23 */
    {0x8812a600u, PROTO_UNKNOWN, 0},
    {0x8812a800u, PROTO_AWS, 21}, /* 136.18.168.0/21 */
    {0x8812b000u, PROTO_UNKNOWN, 0},
    {0x8812fe00u, PROTO_AWS, 23}, /* 136.18.254.0/23 */
    {0x88130000u, PROTO_UNKNOWN, 0},
    {0x88160200u, PROTO_GOOGLE, 23}, /* 136.22.2.0/23 */
    {0x88160600u, PROTO_UNKNOWN, 0},
    {0x88160800u, PROTO_GOOGLE, 21}, /* 136.22.8.0/21 */
    {0x88161000u, PROTO_GOOGLE, 20}, /* 136.22.16.0/20 */
    {0x88162000u, PROTO_UNKNOWN, 0},
    {0x8816a000u, PROTO_GOOGLE, 20}, /* 136.22.160.0/20 */
    {0x8816b000u, PROTO_GOOGLE, 21}, /* 136.22.176.0/21 */
    {0x8816b800u, PROTO_GOOGLE, 23}, /* 136.22.184.0/23 */
    {0x8816ba00u, PROTO_GOOGLE, 24}, /* 136.22.186.0/24 */
    {0x8816bb00u, PROTO_UNKNOWN, 0},
    {0x88170000u, PROTO_GOOGLE, 18}, /* 136.23.0.0/18 */
    {0x88174000u, PROTO_GOOGLE_CLOUD, 18}, /* 136.23.64.0/18 */
    {0x88178000u, PROTO_UNKNOWN, 0},
    {0x88400000u, PROTO_GOOGLE_CLOUD, 13}, /* 136.64.0.0/13 */
    {0x88480000u, PROTO_GOOGLE_CLOUD, 14}, /* 136.72.0.0/14 */
    {0x884c0000u, PROTO_GOOGLE, 16}, /* 136.76.0.0/16 */
    {0x884d0000u, PROTO_GOOGLE_CLOUD, 16}, /* 136.77.0.0/16 */
    {0x884e0000u, PROTO_GOOGLE, 16}, /* 136.78.0.0/16 */
    {0x884f0000u, PROTO_GOOGLE_CLOUD, 16}, /* 136.79.0.0/16 */
    {0x88500000u, PROTO_GOOGLE_CLOUD, 12}, /* 136.80.0.0/12 */
    {0x88600000u, PROTO_UNKNOWN, 0},
    {0x886b0000u, PROTO_GOOGLE_CLOUD, 16}, /* 136.107.0.0/16 */
    {0x886c0000u, PROTO_GOOGLE_CLOUD, 14}, /* 136.108.0.0/14 */
    {0x88700000u, PROTO_GOOGLE_CLOUD, 13}, /* 136.112.0.0/13 */
    {0x88780000u, PROTO_GOOGLE, 22}, /* 136.120.0.0/22 */
    {0x88780400u, PROTO_UNKNOWN, 0},
    {0x88790800u, PROTO_GOOGLE, 21}, /* 136.121.8.0/21 */
    {0x88791000u, PROTO_UNKNOWN, 0},
    {0x887c0000u, PROTO_GOOGLE, 15}, /* 136.124.0.0/15 */
    {0x887e0000u, PROTO_UNKNOWN, 0},
    {0x89740000u, PROTO_AZURE, 18}, /* 137.116.0.0/18 */
    {0x89744000u, PROTO_AZURE, 19}, /* 137.116.64.0/19 */
    {0x89746000u, PROTO_AZURE, 22}, /* 137.116.96.0/22 */
    {0x89746400u, PROTO_UNKNOWN, 0},
    {0x89747000u, PROTO_AZURE, 20}, /* 137.116.112.0/20 */
    {0x89748000u, PROTO_AZURE, 17}, /* 137.116.128.0/17 */
    {0x89750000u, PROTO_AZURE, 16}, /* 137.117.0.0/16 */
    {0x89760000u, PROTO_UNKNOWN, 0},
    {0x89870000u, PROTO_AZURE, 16}, /* 137.135.0.0/16 */
    {0x89880000u, PROTO_UNKNOWN, 0},
    {0x8a5b0000u, PROTO_AZURE, 16}, /* 138.91.0.0/16 */
    {0x8a5c0000u, PROTO_UNKNOWN, 0},
    {0x8b381000u, PROTO_AWS, 20}, /* 139.56.16.0/20 */
    {0x8b382000u, PROTO_AWS, 23}, /* 139.56.32.0/23 */
    {0x8b382200u, PROTO_AWS, 24}, /* 139.56.34.0/24 */
    {0x8b382300u, PROTO_UNKNOWN, 0},
    {0x8b960000u, PROTO_KAKAO, 21}, /* 139.150.0.0/21 */
    {0x8b960100u, PROTO_KAKAO, 24}, /* 139.150.1.0/24 */
    {0x8b960400u, PROTO_KAKAO, 22}, /* 139.150.4.0/22 */
    {0x8b960500u, PROTO_KAKAO, 24}, /* 139.150.5.0/24 */
    {0x8b960800u, PROTO_UNKNOWN, 0},
    {0x8cb30000u, PROTO_AWS, 16}, /* 140.179.0.0/16 */
    {0x8cb40000u, PROTO_UNKNOWN, 0},
    {0x8cf84000u, PROTO_FASTLY, 18}, /* 140.248.64.0/18 */
    {0x8cf88000u, PROTO_FASTLY, 17}, /* 140.248.128.0/17 */
    {0x8cf90000u, PROTO_UNKNOWN, 0},
    {0x8d654000u, PROTO_CLOUDFLARE, 18}, /* 141.101.64.0/18 */
    {0x8d658000u, PROTO_UNKNOWN, 0},
    {0x8de60000u, PROTO_AWS, 15}, /* 141.230.0.0/15 */
    {0x8de80000u, PROTO_UNKNOWN, 0},
    {0x8e04b100u, PROTO_AWS, 24}, /* 142.4.177.0/24 */
    {0x8e04b200u, PROTO_AWS, 23}, /* 142.4.178.0/23 */
    {0x8e04b400u, PROTO_AWS, 24}, /* 142.4.180.0/24 */
    {0x8e04b500u, PROTO_UNKNOWN, 0},
    {0x8efa0000u, PROTO_GOOGLE, 15}, /* 142.250.0.0/15 */
    {0x8efc0000u, PROTO_UNKNOWN, 0},
    {0x8fcc0000u, PROTO_CLOUDFRONT, 16}, /* 143.204.0.0/16 */
    {0x8fcd0000u, PROTO_UNKNOWN, 0},
    {0x90b20000u, PROTO_APPLE, 18}, /* 144.178.0.0/18 */
    {0x90b24000u, PROTO_UNKNOWN, 0},
    {0x90dc0000u, PROTO_CLOUDFRONT, 16}, /* 144.220.0.0/16 */
    {0x90dd0000u, PROTO_UNKNOWN, 0},
    {0x91840000u, PROTO_AZURE, 15}, /* 145.132.0.0/15 */
    {0x91860000u, PROTO_UNKNOWN, 0},
    {0x91be0000u, PROTO_AZURE, 15}, /* 145.190.0.0/15 */
    {0x91c00000u, PROTO_UNKNOWN, 0},
    {0x924b0000u, PROTO_FASTLY, 17}, /* 146.75.0.0/17 */
    {0x924b8000u, PROTO_UNKNOWN, 0},
    {0x92940000u, PROTO_GOOGLE, 23}, /* 146.148.0.0/23 */
    {0x92940200u, PROTO_GOOGLE_CLOUD, 23}, /* 146.148.2.0/23 */
    {0x92940400u, PROTO_GOOGLE_CLOUD, 22}, /* 146.148.4.0/22 */
    {0x92940800u, PROTO_GOOGLE_CLOUD, 21}, /* 146.148.8.0/21 */
    {0x92941000u, PROTO_GOOGLE_CLOUD, 20}, /* 146.148.16.0/20 */
    {0x92942000u, PROTO_GOOGLE_CLOUD, 19}, /* 146.148.32.0/19 */
    {0x92944000u, PROTO_GOOGLE_CLOUD, 18}, /* 146.148.64.0/18 */
    {0x92948000u, PROTO_UNKNOWN, 0},
    {0x95804000u, PROTO_AWS, 18}, /* 149.128.64.0/18 */
    {0x95808000u, PROTO_UNKNOWN, 0},
    {0x96660000u, PROTO_AWS, 15}, /* 150.102.0.0/15 */
    {0x96680000u, PROTO_UNKNOWN, 0},
    {0x96de0000u, PROTO_AWS, 21}, /* 150.222.0.0/21 */
    {0x96de0800u, PROTO_AWS, 22}, /* 150.222.8.0/22 */
    {0x96de0c00u, PROTO_AWS, 23}, /* 150.222.12.0/23 */
    {0x96de0e00u, PROTO_AWS, 24}, /* 150.222.14.0/24 */
    {0x96de0f00u, PROTO_UNKNOWN, 0},
    {0x96de0f7cu, PROTO_AWS, 30}, /* 150.222.15.124/30 */
    {0x96de0f84u, PROTO_AWS, 31}, /* 150.222.15.132/31 */
    {0x96de0f86u, PROTO_UNKNOWN, 0},
    {0x96de1820u, PROTO_AWS, 29}, /* 150.222.24.32/29 */
    {0x96de1828u, PROTO_UNKNOWN, 0},
    {0x96de1840u, PROTO_AWS, 29}, /* 150.222.24.64/29 */
    {0x96de1848u, PROTO_UNKNOWN, 0},
    {0x96de1920u, PROTO_AWS, 29}, /* 150.222.25.32/29 */
    {0x96de1928u, PROTO_UNKNOWN, 0},
    {0x96de1a00u, PROTO_AWS, 23}, /* 150.222.26.0/23 */
    {0x96de1c00u, PROTO_AWS, 22}, /* 150.222.28.0/22 */
    {0x96de2000u, PROTO_AWS, 21}, /* 150.222.32.0/21 */
    {0x96de2800u, PROTO_AWS, 22}, /* 150.222.40.0/22 */
    {0x96de2c00u, PROTO_AWS, 24}, /* 150.222.44.0/24 */
    {0x96de2d00u, PROTO_AWS, 26}, /* 150.222.45.0/26 */
    {0x96de2d40u, PROTO_AWS, 27}, /* 150.222.45.64/27 */
    {0x96de2d60u, PROTO_UNKNOWN, 0},
    {0x96de2d80u, PROTO_AWS, 25}, /* 150.222.45.128/25 */
    {0x96de2e00u, PROTO_AWS, 23}, /* 150.222.46.0/23 */
    {0x96de3000u, PROTO_AWS, 21}, /* 150.222.48.0/21 */
    {0x96de3800u, PROTO_AWS, 27}, /* 150.222.56.0/27 */
    {0x96de3820u, PROTO_UNKNOWN, 0},
    {0x96de4000u, PROTO_AWS, 22}, /* 150.222.64.0/22 */
    {0x96de4400u, PROTO_UNKNOWN, 0},
    {0x96de4474u, PROTO_AWS, 31}, /* 150.222.68.116/31 */
    {0x96de4476u, PROTO_UNKNOWN, 0},
    {0x96de4500u, PROTO_AWS, 24}, /* 150.222.69.0/24 */
    {0x96de4600u, PROTO_AWS, 23}, /* 150.222.70.0/23 */
    {0x96de4800u, PROTO_AWS, 21}, /* 150.222.72.0/21 */
    {0x96de5000u, PROTO_AWS, 20}, /* 150.222.80.0/20 */
    {0x96de7000u, PROTO_AWS, 21}, /* 150.222.112.0/21 */
    {0x96de7800u, PROTO_AWS, 22}, /* 150.222.120.0/22 */
    {0x96de7c00u, PROTO_UNKNOWN, 0},
    {0x96de8100u, PROTO_AWS, 24}, /* 150.222.129.0/24 */
    {0x96de8200u, PROTO_UNKNOWN, 0},
    {0x96de8500u, PROTO_AWS, 24}, /* 150.222.133.0/24 */
    {0x96de8600u, PROTO_AWS, 23}, /* 150.222.134.0/23 */
    {0x96de8a00u, PROTO_AWS, 24}, /* 150.222.138.0/24 */
    {0x96de8b00u, PROTO_UNKNOWN, 0},
    {0x96de8b74u, PROTO_AWS, 30}, /* 150.222.139.116/30 */
    {0x96de8b78u, PROTO_AWS, 29}, /* 150.222.139.120/29 */
    {0x96de8b80u, PROTO_UNKNOWN, 0},
    {0x96de8c00u, PROTO_AWS, 22}, /* 150.222.140.0/22 */
    {0x96de9000u, PROTO_UNKNOWN, 0},
    {0x96de9020u, PROTO_AWS, 29}, /* 150.222.144.32/29 */
    {0x96de9028u, PROTO_UNKNOWN, 0},
    {0x96de9040u, PROTO_AWS, 29}, /* 150.222.144.64/29 */
    {0x96de9048u, PROTO_UNKNOWN, 0},
    {0x96de9060u, PROTO_AWS, 29}, /* 150.222.144.96/29 */
    {0x96de9068u, PROTO_UNKNOWN, 0},
    {0x96de9820u, PROTO_AWS, 29}, /* 150.222.152.32/29 */
    {0x96de9828u, PROTO_UNKNOWN, 0},
    {0x96de9840u, PROTO_AWS, 29}, /* 150.222.152.64/29 */
    {0x96de9848u, PROTO_UNKNOWN, 0},
    {0x96de9860u, PROTO_AWS, 29}, /* 150.222.152.96/29 */
    {0x96de9868u, PROTO_UNKNOWN, 0},
    {0x96dea020u, PROTO_AWS, 29}, /* 150.222.160.32/29 */
    {0x96dea028u, PROTO_UNKNOWN, 0},
    {0x96dea4d0u, PROTO_AWS, 29}, /* 150.222.164.208/29 */
    {0x96dea4d8u, PROTO_UNKNOWN, 0},
    {0x96dea4dcu, PROTO_AWS, 31}, /* 150.222.164.220/31 */
    {0x96dea4deu, PROTO_AWS, 32}, /* 150.222.164.222/32 */
    {0x96dea4dfu, PROTO_UNKNOWN, 0},
    {0x96dea820u, PROTO_AWS, 29}, /* 150.222.168.32/29 */
    {0x96dea828u, PROTO_UNKNOWN, 0},
    {0x96deb000u, PROTO_AWS, 22}, /* 150.222.176.0/22 */
    {0x96deb400u, PROTO_AWS, 24}, /* 150.222.180.0/24 */
    {0x96deb500u, PROTO_UNKNOWN, 0},
    {0x96deb60eu, PROTO_AWS, 31}, /* 150.222.182.14/31 */
    {0x96deb612u, PROTO_UNKNOWN, 0},
    {0x96dec400u, PROTO_AWS, 24}, /* 150.222.196.0/24 */
    {0x96dec500u, PROTO_UNKNOWN, 0},
    {0x96dec700u, PROTO_AWS, 25}, /* 150.222.199.0/25 */
    {0x96dec780u, PROTO_UNKNOWN, 0},
    {0x96dec83cu, PROTO_AWS, 31}, /* 150.222.200.60/31 */
    {0x96dec83eu, PROTO_UNKNOWN, 0},
    {0x96deca00u, PROTO_AWS, 23}, /* 150.222.202.0/23 */
    {0x96decc00u, PROTO_AWS, 22}, /* 150.222.204.0/22 */
    {0x96ded000u, PROTO_AWS, 24}, /* 150.222.208.0/24 */
    {0x96ded100u, PROTO_UNKNOWN, 0},
    {0x96ded200u, PROTO_AWS, 23}, /* 150.222.210.0/23 */
    {0x96ded400u, PROTO_AWS, 22}, /* 150.222.212.0/22 */
    {0x96ded800u, PROTO_AWS, 21}, /* 150.222.216.0/21 */
    {0x96dee000u, PROTO_AWS, 24}, /* 150.222.224.0/24 */
    {0x96dee100u, PROTO_UNKNOWN, 0},
    {0x96dee200u, PROTO_AWS, 23}, /* 150.222.226.0/23 */
    {0x96dee400u, PROTO_AWS, 22}, /* 150.222.228.0/22 */
    {0x96dee800u, PROTO_AWS, 23}, /* 150.222.232.0/23 */
    {0x96deea00u, PROTO_AWS, 26}, /* 150.222.234.0/26 */
    {0x96deea40u, PROTO_AWS, 28}, /* 150.222.234.64/28 */
    {0x96deea50u, PROTO_AWS, 29}, /* 150.222.234.80/29 */
    {0x96deea58u, PROTO_UNKNOWN, 0},
    {0x96deea60u, PROTO_AWS, 27}, /* 150.222.234.96/27 */
    {0x96deea80u, PROTO_AWS, 28}, /* 150.222.234.128/28 */
    {0x96deea90u, PROTO_UNKNOWN, 0},
    {0x96deeb00u, PROTO_AWS, 24}, /* 150.222.235.0/24 */
    {0x96deec00u, PROTO_AWS, 22}, /* 150.222.236.0/22 */
    {0x96def000u, PROTO_UNKNOWN, 0},
    {0x96def254u, PROTO_AWS, 31}, /* 150.222.242.84/31 */
    {0x96def256u, PROTO_UNKNOWN, 0},
    {0x96def2d6u, PROTO_AWS, 31}, /* 150.222.242.214/31 */
    {0x96def2d8u, PROTO_UNKNOWN, 0},
    {0x96def57au, PROTO_AWS, 31}, /* 150.222.245.122/31 */
    {0x96def57cu, PROTO_UNKNOWN, 0},
    {0x96defcf4u, PROTO_AWS, 30}, /* 150.222.252.244/30 */
    {0x96defcfcu, PROTO_UNKNOWN, 0},
    {0x96f72000u, PROTO_AWS, 22}, /* 150.247.32.0/22 */
    {0x96f72400u, PROTO_AWS, 23}, /* 150.247.36.0/23 */
    {0x96f72600u, PROTO_UNKNOWN, 0},
    {0x96f72700u, PROTO_AWS, 24}, /* 150.247.39.0/24 */
    {0x96f72800u, PROTO_AWS, 21}, /* 150.247.40.0/21 */
    {0x96f73000u, PROTO_UNKNOWN, 0},
    {0x97650000u, PROTO_FASTLY, 16}, /* 151.101.0.0/16 */
    {0x97660000u, PROTO_UNKNOWN, 0},
    {0x97940800u, PROTO_AWS, 21}, /* 151.148.8.0/21 */
    {0x97941000u, PROTO_AWS, 30}, /* 151.148.16.0/30 */
    {0x97941004u, PROTO_AWS, 31}, /* 151.148.16.4/31 */
    {0x97941006u, PROTO_AWS, 32}, /* 151.148.16.6/32 */
    {0x97941007u, PROTO_UNKNOWN, 0},
    {0x97941008u, PROTO_AWS, 30}, /* 151.148.16.8/30 */
    {0x9794100cu, PROTO_UNKNOWN, 0},
    {0x97941100u, PROTO_AWS, 24}, /* 151.148.17.0/24 */
    {0x97941200u, PROTO_AWS, 23}, /* 151.148.18.0/23 */
    {0x97941400u, PROTO_AWS, 24}, /* 151.148.20.0/24 */
    {0x97941500u, PROTO_UNKNOWN, 0},
    {0x97942000u, PROTO_AWS, 21}, /* 151.148.32.0/21 */
    {0x97942800u, PROTO_AWS, 23}, /* 151.148.40.0/23 */
    {0x97942a00u, PROTO_UNKNOWN, 0},
    {0x97ce3000u, PROTO_AZURE, 20}, /* 151.206.48.0/20 */
    {0x97ce4000u, PROTO_AZURE, 18}, /* 151.206.64.0/18 */
    {0x97cec000u, PROTO_AZURE, 23}, /* 151.206.192.0/23 */
    {0x97cec200u, PROTO_AZURE, 24}, /* 151.206.194.0/24 */
    {0x97cec300u, PROTO_UNKNOWN, 0},
    {0x98ee0000u, PROTO_GOOGLE, 16}, /* 152.238.0.0/16 */
    {0x98ef0000u, PROTO_UNKNOWN, 0},
    {0x98ef8000u, PROTO_GOOGLE_CLOUD, 17}, /* 152.239.128.0/17 */
    {0x98f00000u, PROTO_UNKNOWN, 0},
    {0x9a210000u, PROTO_YAHOO, 24}, /* 154.33.0.0/24 */
    {0x9a210100u, PROTO_UNKNOWN, 0},
    {0x9a220000u, PROTO_YAHOO, 24}, /* 154.34.0.0/24 */
    {0x9a220100u, PROTO_UNKNOWN, 0},
    {0x9a224000u, PROTO_YAHOO, 18}, /* 154.34.64.0/18 */
    {0x9a228000u, PROTO_YAHOO, 17}, /* 154.34.128.0/17 */
    {0x9a22e000u, PROTO_YAHOO, 20}, /* 154.34.224.0/20 */
    {0x9a230000u, PROTO_UNKNOWN, 0},
    {0x9b920000u, PROTO_AWS, 16}, /* 155.146.0.0/16 */
    {0x9b930000u, PROTO_UNKNOWN, 0},
    {0x9c040000u, PROTO_AWS, 15}, /* 156.4.0.0/15 */
    {0x9c060000u, PROTO_UNKNOWN, 0},
    {0x9d344000u, PROTO_FASTLY, 18}, /* 157.52.64.0/18 */
    {0x9d348000u, PROTO_UNKNOWN, 0},
    {0x9d370280u, PROTO_AZURE, 26}, /* 157.55.2.128/26 */
    {0x9d3702c0u, PROTO_UNKNOWN, 0},
    {0x9d370780u, PROTO_AZURE, 26}, /* 157.55.7.128/26 */
    {0x9d3707c0u, PROTO_UNKNOWN, 0},
    {0x9d370840u, PROTO_AZURE, 26}, /* 157.55.8.64/26 */
    {0x9d370880u, PROTO_UNKNOWN, 0},
    {0x9d370890u, PROTO_AZURE, 28}, /* 157.55.8.144/28 */
    {0x9d3708a0u, PROTO_UNKNOWN, 0},
    {0x9d370aa0u, PROTO_AZURE, 29}, /* 157.55.10.160/29 */
    {0x9d370aa8u, PROTO_UNKNOWN, 0},
    {0x9d370ab0u, PROTO_AZURE, 28}, /* 157.55.10.176/28 */
    {0x9d370ac0u, PROTO_AZURE, 26}, /* 157.55.10.192/26 */
    {0x9d370b00u, PROTO_UNKNOWN, 0},
    {0x9d370b80u, PROTO_AZURE, 25}, /* 157.55.11.128/25 */
    {0x9d370c00u, PROTO_UNKNOWN, 0},
    {0x9d370c40u, PROTO_AZURE, 26}, /* 157.55.12.64/26 */
    {0x9d370cc0u, PROTO_UNKNOWN, 0},
    {0x9d370d40u, PROTO_AZURE, 26}, /* 157.55.13.64/26 */
    {0x9d370dc0u, PROTO_UNKNOWN, 0},
    {0x9d372500u, PROTO_AZURE, 24}, /* 157.55.37.0/24 */
    {0x9d372600u, PROTO_AZURE, 23}, /* 157.55.38.0/23 */
    {0x9d372800u, PROTO_UNKNOWN, 0},
    {0x9d373000u, PROTO_AZURE, 24}, /* 157.55.48.0/24 */
    {0x9d373100u, PROTO_UNKNOWN, 0},
    {0x9d373200u, PROTO_AZURE, 25}, /* 157.55.50.0/25 */
    {0x9d373280u, PROTO_UNKNOWN, 0},
    {0x9d373700u, PROTO_AZURE, 27}, /* 157.55.55.0/27 */
    {0x9d373720u, PROTO_AZURE, 28}, /* 157.55.55.32/28 */
    {0x9d373730u, PROTO_UNKNOWN, 0},
    {0x9d373764u, PROTO_AZURE, 30}, /* 157.55.55.100/30 */
    {0x9d373768u, PROTO_AZURE, 29}, /* 157.55.55.104/29 */
    {0x9d373770u, PROTO_UNKNOWN, 0},
    {0x9d373788u, PROTO_AZURE, 29}, /* 157.55.55.136/29 */
    {0x9d373790u, PROTO_AZURE, 28}, /* 157.55.55.144/28 */
    {0x9d3737b0u, PROTO_AZURE, 29}, /* 157.55.55.176/29 */
    {0x9d3737b8u, PROTO_UNKNOWN, 0},
    {0x9d3737c8u, PROTO_AZURE, 29}, /* 157.55.55.200/29 */
    {0x9d3737d0u, PROTO_UNKNOWN, 0},
    {0x9d3737d8u, PROTO_AZURE, 29}, /* 157.55.55.216/29 */
    {0x9d3737e0u, PROTO_UNKNOWN, 0},
    {0x9d3737e4u, PROTO_AZURE, 30}, /* 157.55.55.228/30 */
    {0x9d3737e8u, PROTO_AZURE, 29}, /* 157.55.55.232/29 */
    {0x9d3737f0u, PROTO_AZURE, 28}, /* 157.55.55.240/28 */
    {0x9d373800u, PROTO_UNKNOWN, 0},
    {0x9d373ce0u, PROTO_AZURE, 27}, /* 157.55.60.224/27 */
    {0x9d373d00u, PROTO_UNKNOWN, 0},
    {0x9d374000u, PROTO_AZURE, 19}, /* 157.55.64.0/19 */
    {0x9d376000u, PROTO_UNKNOWN, 0},
    {0x9d376720u, PROTO_AZURE, 27}, /* 157.55.103.32/27 */
    {0x9d376740u, PROTO_UNKNOWN, 0},
    {0x9d376780u, PROTO_AZURE, 25}, /* 157.55.103.128/25 */
    {0x9d376800u, PROTO_UNKNOWN, 0},
    {0x9d376a00u, PROTO_AZURE, 26}, /* 157.55.106.0/26 */
    {0x9d376a40u, PROTO_UNKNOWN, 0},
    {0x9d376a80u, PROTO_AZURE, 25}, /* 157.55.106.128/25 */
    {0x9d376b00u, PROTO_AZURE, 24}, /* 157.55.107.0/24 */
    {0x9d376c00u, PROTO_AZURE, 22}, /* 157.55.108.0/22 */
    {0x9d377000u, PROTO_UNKNOWN, 0},
    {0x9d378800u, PROTO_AZURE, 21}, /* 157.55.136.0/21 */
    {0x9d379000u, PROTO_UNKNOWN, 0},
    {0x9d3799e0u, PROTO_AZURE, 28}, /* 157.55.153.224/28 */
    {0x9d3799f0u, PROTO_UNKNOWN, 0},
    {0x9d379a80u, PROTO_AZURE, 25}, /* 157.55.154.128/25 */
    {0x9d379b00u, PROTO_UNKNOWN, 0},
    {0x9d37a000u, PROTO_AZURE, 19}, /* 157.55.160.0/19 */
    {0x9d37c000u, PROTO_AZURE, 21}, /* 157.55.192.0/21 */
    {0x9d37c800u, PROTO_AZURE, 22}, /* 157.55.200.0/22 */
    {0x9d37cc00u, PROTO_UNKNOWN, 0},
    {0x9d37cc01u, PROTO_AZURE, 32}, /* 157.55.204.1/32 */
    {0x9d37cc02u, PROTO_AZURE, 31}, /* 157.55.204.2/31 */
    {0x9d37cc04u, PROTO_UNKNOWN, 0},
    {0x9d37cc21u, PROTO_AZURE, 32}, /* 157.55.204.33/32 */
    {0x9d37cc22u, PROTO_AZURE, 31}, /* 157.55.204.34/31 */
    {0x9d37cc24u, PROTO_UNKNOWN, 0},
    {0x9d37cc80u, PROTO_AZURE, 25}, /* 157.55.204.128/25 */
    {0x9d37cd00u, PROTO_UNKNOWN, 0},
    {0x9d37d000u, PROTO_AZURE, 21}, /* 157.55.208.0/21 */
    {0x9d37d800u, PROTO_UNKNOWN, 0},
    {0x9d37f800u, PROTO_AZURE, 21}, /* 157.55.248.0/21 */
    {0x9d380000u, PROTO_UNKNOWN, 0},
    {0x9d380200u, PROTO_AZURE, 23}, /* 157.56.2.0/23 */
    {0x9d380400u, PROTO_UNKNOWN, 0},
    {0x9d380800u, PROTO_AZURE, 21}, /* 157.56.8.0/21 */
    {0x9d381000u, PROTO_UNKNOWN, 0},
    {0x9d3818a0u, PROTO_AZURE, 27}, /* 157.56.24.160/27 */
    {0x9d3818e0u, PROTO_UNKNOWN, 0},
    {0x9d381c00u, PROTO_AZURE, 22}, /* 157.56.28.0/22 */
    {0x9d382000u, PROTO_UNKNOWN, 0},
    {0x9d385000u, PROTO_AZURE, 25}, /* 157.56.80.0/25 */
    {0x9d385080u, PROTO_UNKNOWN, 0},
    {0x9d38a000u, PROTO_AZURE, 21}, /* 157.56.160.0/21 */
    {0x9d38a800u, PROTO_UNKNOWN, 0},
    {0x9d38b000u, PROTO_AZURE, 21}, /* 157.56.176.0/21 */
    {0x9d38b800u, PROTO_UNKNOWN, 0},
    {0x9d38d800u, PROTO_AZURE, 26}, /* 157.56.216.0/26 */
    {0x9d38d840u, PROTO_UNKNOWN, 0},
    {0x9daf0000u, PROTO_AWS, 16}, /* 157.175.0.0/16 */
    {0x9db00000u, PROTO_UNKNOWN, 0},
    {0x9df00000u, PROTO_FACEBOOK, 16}, /* 157.240.0.0/16 */
    {0x9df00100u, PROTO_FACEBOOK, 24}, /* 157.240.1.0/24 */
    {0x9df00b00u, PROTO_FACEBOOK, 16}, /* 157.240.0.0/16 */
    {0x9df10000u, PROTO_AWS, 16}, /* 157.241.0.0/16 */
    {0x9df20000u, PROTO_UNKNOWN, 0},
    {0x9e170000u, PROTO_AZURE, 16}, /* 158.23.0.0/16 */
    {0x9e180000u, PROTO_UNKNOWN, 0},
    {0x9e9e0000u, PROTO_AZURE, 16}, /* 158.158.0.0/16 */
    {0x9e9f0000u, PROTO_UNKNOWN, 0},
    {0x9ecd0000u, PROTO_YAHOO, 24}, /* 158.205.0.0/24 */
    {0x9ecd0100u, PROTO_UNKNOWN, 0},
    {0x9ecd7900u, PROTO_YAHOO, 24}, /* 158.205.121.0/24 */
    {0x9ecd7a00u, PROTO_UNKNOWN, 0},
    {0x9efc0000u, PROTO_AWS, 15}, /* 158.252.0.0/15 */
    {0x9efe0000u, PROTO_UNKNOWN, 0},
    {0x9ff88500u, PROTO_AWS, 24}, /* 159.248.133.0/24 */
    {0x9ff88600u, PROTO_UNKNOWN, 0},
    {0x9ff8c800u, PROTO_AWS, 21}, /* 159.248.200.0/21 */
    {0x9ff8d000u, PROTO_UNKNOWN, 0},
    {0x9ff8d800u, PROTO_AWS, 21}, /* 159.248.216.0/21 */
    {0x9ff8e000u, PROTO_AWS, 20}, /* 159.248.224.0/20 */
    {0x9ff8f000u, PROTO_AWS, 21}, /* 159.248.240.0/21 */
    {0x9ff8f800u, PROTO_UNKNOWN, 0},
    {0xa0010000u, PROTO_AWS, 16}, /* 160.1.0.0/16 */
    {0xa0020000u, PROTO_UNKNOWN, 0},
    {0xa01e8000u, PROTO_YAHOO, 17}, /* 160.30.128.0/17 */
    {0xa01f0000u, PROTO_UNKNOWN, 0},
    {0xa1b20000u, PROTO_AWS, 18}, /* 161.178.0.0/18 */
    {0xa1b24000u, PROTO_UNKNOWN, 0},
    {0xa1b28000u, PROTO_AWS, 18}, /* 161.178.128.0/18 */
    {0xa1b2c000u, PROTO_UNKNOWN, 0},
    {0xa1bc0000u, PROTO_AWS, 18}, /* 161.188.0.0/18 */
    {0xa1bc4000u, PROTO_AWS, 19}, /* 161.188.64.0/19 */
    {0xa1bc6000u, PROTO_UNKNOWN, 0},
    {0xa1bc7000u, PROTO_AWS, 21}, /* 161.188.112.0/21 */
    {0xa1bc7800u, PROTO_AWS, 22}, /* 161.188.120.0/22 */
    {0xa1bc7c00u, PROTO_UNKNOWN, 0},
    {0xa1bc7f00u, PROTO_AWS, 24}, /* 161.188.127.0/24 */
    {0xa1bc8000u, PROTO_UNKNOWN, 0},
    {0xa1bd0000u, PROTO_AWS, 16}, /* 161.189.0.0/16 */
    {0xa1be0000u, PROTO_UNKNOWN, 0},
    {0xa1c10000u, PROTO_AWS, 18}, /* 161.193.0.0/18 */
    {0xa1c14000u, PROTO_UNKNOWN, 0},
    {0xa1c18000u, PROTO_AWS, 18}, /* 161.193.128.0/18 */
    {0xa1c1c000u, PROTO_UNKNOWN, 0},
    {0xa2788000u, PROTO_GOOGLE, 17}, /* 162.120.128.0/17 */
    {0xa2790000u, PROTO_UNKNOWN, 0},
    {0xa29e0000u, PROTO_CLOUDFLARE, 15}, /* 162.158.0.0/15 */
    {0xa2a00000u, PROTO_UNKNOWN, 0},
    {0xa2d01400u, PROTO_YAHOO, 22}, /* 162.208.20.0/22 */
    {0xa2d01500u, PROTO_YAHOO, 24}, /* 162.208.21.0/24 */
    {0xa2d01600u, PROTO_YAHOO, 23}, /* 162.208.22.0/23 */
    {0xa2d01700u, PROTO_YAHOO, 24}, /* 162.208.23.0/24 */
    {0xa2d01800u, PROTO_UNKNOWN, 0},
    {0xa2d07900u, PROTO_AWS, 24}, /* 162.208.121.0/24 */
    {0xa2d07a00u, PROTO_UNKNOWN, 0},
    {0xa2d5e800u, PROTO_AWS, 22}, /* 162.213.232.0/22 */
    {0xa2d5ec00u, PROTO_UNKNOWN, 0},
    {0xa2d89400u, PROTO_GOOGLE_CLOUD, 22}, /* 162.216.148.0/22 */
    {0xa2d89800u, PROTO_UNKNOWN, 0},
    {0xa2de9400u, PROTO_AWS, 22}, /* 162.222.148.0/22 */
    {0xa2de9800u, PROTO_UNKNOWN, 0},
    {0xa2deb000u, PROTO_GOOGLE_CLOUD, 21}, /* 162.222.176.0/21 */
    {0xa2deb800u, PROTO_UNKNOWN, 0},
    {0xa2faec00u, PROTO_AWS, 22}, /* 162.250.236.0/22 */
    {0xa2faf000u, PROTO_UNKNOWN, 0},
    {0xa42e0000u, PROTO_YAHOO, 16}, /* 164.46.0.0/16 */
    {0xa42f0000u, PROTO_UNKNOWN, 0},
    {0xa6750000u, PROTO_AWS, 16}, /* 166.117.0.0/16 */
    {0xa6760000u, PROTO_UNKNOWN, 0},
    {0xa7520000u, PROTO_FASTLY, 17}, /* 167.82.0.0/17 */
    {0xa7528000u, PROTO_FASTLY, 20}, /* 167.82.128.0/20 */
    {0xa7529000u, PROTO_UNKNOWN, 0},
    {0xa752a000u, PROTO_FASTLY, 20}, /* 167.82.160.0/20 */
    {0xa752b000u, PROTO_UNKNOWN, 0},
    {0xa752e000u, PROTO_FASTLY, 20}, /* 167.82.224.0/20 */
    {0xa752f000u, PROTO_UNKNOWN, 0},
    {0xa7690000u, PROTO_AZURE, 16}, /* 167.105.0.0/16 */
    {0xa76a0000u, PROTO_UNKNOWN, 0},
    {0xa83d0000u, PROTO_AZURE, 16}, /* 168.61.0.0/16 */
    {0xa83e0000u, PROTO_AZURE, 15}, /* 168.62.0.0/15 */
    {0xa8400000u, PROTO_UNKNOWN, 0},
    {0xa8726300u, PROTO_APPLE, 24}, /* 168.114.99.0/24 */
    {0xa8726400u, PROTO_UNKNOWN, 0},
    {0xa872f000u, PROTO_APPLE, 24}, /* 168.114.240.0/24 */
    {0xa872f100u, PROTO_UNKNOWN, 0},
    {0xa8b90400u, PROTO_AWS, 22}, /* 168.185.4.0/22 */
    {0xa8b90800u, PROTO_UNKNOWN, 0},
    {0xa8c00000u, PROTO_AWS, 15}, /* 168.192.0.0/15 */
    {0xa8c20000u, PROTO_UNKNOWN, 0},
    {0xac400000u, PROTO_CLOUDFLARE, 13}, /* 172.64.0.0/13 */
    {0xac480000u, PROTO_UNKNOWN, 0},
    {0xac606100u, PROTO_AWS, 24}, /* 172.96.97.0/24 */
    {0xac606300u, PROTO_UNKNOWN, 0},
    {0xac606e00u, PROTO_AWS, 24}, /* 172.96.110.0/24 */
    {0xac606f00u, PROTO_UNKNOWN, 0},
    {0xac660800u, PROTO_GOOGLE, 21}, /* 172.102.8.0/21 */
    {0xac661000u, PROTO_UNKNOWN, 0},
    {0xac6a0000u, PROTO_AWS, 15}, /* 172.106.0.0/15 */
    {0xac6c0000u, PROTO_UNKNOWN, 0},
    {0xac6e2000u, PROTO_GOOGLE, 21}, /* 172.110.32.0/21 */
    {0xac6e2800u, PROTO_UNKNOWN, 0},
    {0xac6f4000u, PROTO_FASTLY, 18}, /* 172.111.64.0/18 */
    {0xac6f8000u, PROTO_UNKNOWN, 0},
    {0xac800000u, PROTO_AZURE, 10}, /* 172.128.0.0/10 */
    {0xacc00000u, PROTO_AZURE, 12}, /* 172.192.0.0/12 */
    {0xacd00000u, PROTO_AZURE, 13}, /* 172.208.0.0/13 */
    {0xacd80000u, PROTO_UNKNOWN, 0},
    {0xacd90000u, PROTO_GOOGLE, 16}, /* 172.217.0.0/16 */
    {0xacda0000u, PROTO_UNKNOWN, 0},
    {0xacfd0000u, PROTO_GOOGLE, 16}, /* 172.253.0.0/16 */
    {0xacfe0000u, PROTO_UNKNOWN, 0},
    {0xad53c000u, PROTO_AWS, 19}, /* 173.83.192.0/19 */
    {0xad53e000u, PROTO_AWS, 21}, /* 173.83.224.0/21 */
    {0xad53e800u, PROTO_AWS, 22}, /* 173.83.232.0/22 */
    {0xad53ec00u, PROTO_AWS, 23}, /* 173.83.236.0/23 */
    {0xad53ee00u, PROTO_AWS, 24}, /* 173.83.238.0/24 */
    {0xad53ef00u, PROTO_UNKNOWN, 0},
    {0xadc20000u, PROTO_GOOGLE, 16}, /* 173.194.0.0/16 */
    {0xadc30000u, PROTO_UNKNOWN, 0},
    {0xadf30000u, PROTO_WEBEX, 20}, /* 173.243.0.0/20 */
    {0xadf31000u, PROTO_UNKNOWN, 0},
    {0xadf53000u, PROTO_CLOUDFLARE, 20}, /* 173.245.48.0/20 */
    {0xadf54000u, PROTO_UNKNOWN, 0},
    {0xadfc4000u, PROTO_FACEBOOK, 18}, /* 173.252.64.0/18 */
    {0xadfc4600u, PROTO_FACEBOOK, 24}, /* 173.252.70.0/24 */
    {0xadfc4700u, PROTO_FACEBOOK, 18}, /* 173.252.64.0/18 */
    {0xadfc6000u, PROTO_FACEBOOK, 19}, /* 173.252.96.0/19 */
    {0xadfc8000u, PROTO_UNKNOWN, 0},
    {0xadff7000u, PROTO_GOOGLE_CLOUD, 20}, /* 173.255.112.0/20 */
    {0xadff8000u, PROTO_UNKNOWN, 0},
    {0xae810000u, PROTO_AWS, 16}, /* 174.129.0.0/16 */
    {0xae820000u, PROTO_UNKNOWN, 0},
    {0xaf298000u, PROTO_AWS, 17}, /* 175.41.128.0/17 */
    {0xaf2a0000u, PROTO_UNKNOWN, 0},
    {0xb0204000u, PROTO_AWS, 19}, /* 176.32.64.0/19 */
    {0xb0206000u, PROTO_AWS, 20}, /* 176.32.96.0/20 */
    {0xb0207000u, PROTO_AWS, 21}, /* 176.32.112.0/21 */
    {0xb0207800u, PROTO_AWS, 22}, /* 176.32.120.0/22 */
    {0xb0207c00u, PROTO_UNKNOWN, 0},
    {0xb0207c80u, PROTO_AWS, 25}, /* 176.32.124.128/25 */
    {0xb0207d00u, PROTO_AWS, 24}, /* 176.32.125.0/24 */
    {0xb0207e00u, PROTO_UNKNOWN, 0},
    {0xb0220000u, PROTO_AWS, 16}, /* 176.34.0.0/16 */
    {0xb0230000u, PROTO_UNKNOWN, 0},
    {0xb1478000u, PROTO_AWS, 17}, /* 177.71.128.0/17 */
    {0xb1480000u, PROTO_UNKNOWN, 0},
    {0xb148f000u, PROTO_AWS, 21}, /* 177.72.240.0/21 */
    {0xb148f800u, PROTO_UNKNOWN, 0},
    {0xb1b00000u, PROTO_GOOGLE, 16}, /* 177.176.0.0/16 */
    {0xb1b10000u, PROTO_UNKNOWN, 0},
    {0xb1b20000u, PROTO_GOOGLE, 15}, /* 177.178.0.0/15 */
    {0xb1b40000u, PROTO_UNKNOWN, 0},
    {0xb1d00000u, PROTO_GOOGLE, 15}, /* 177.208.0.0/15 */
    {0xb1d20000u, PROTO_UNKNOWN, 0},
    {0xb2ec0000u, PROTO_AWS, 20}, /* 178.236.0.0/20 */
    {0xb2ec1000u, PROTO_UNKNOWN, 0},
    {0xb33cc000u, PROTO_FACEBOOK, 22}, /* 179.60.192.0/22 */
    {0xb33cc100u, PROTO_FACEBOOK, 24}, /* 179.60.193.0/24 */
    {0xb33cc400u, PROTO_UNKNOWN, 0},
    {0xb3430000u, PROTO_GOOGLE_CLOUD, 17}, /* 179.67.0.0/17 */
    {0xb3438000u, PROTO_UNKNOWN, 0},
    {0xb3458000u, PROTO_GOOGLE_CLOUD, 17}, /* 179.69.128.0/17 */
    {0xb3460000u, PROTO_UNKNOWN, 0},
    {0xb3c18000u, PROTO_GOOGLE_CLOUD, 17}, /* 179.193.128.0/17 */
    {0xb3c20000u, PROTO_UNKNOWN, 0},
    {0xb3c70000u, PROTO_GOOGLE_CLOUD, 17}, /* 179.199.0.0/17 */
    {0xb3c78000u, PROTO_UNKNOWN, 0},
    {0xb4a33900u, PROTO_CLOUDFRONT, 25}, /* 180.163.57.0/25 */
    {0xb4a33980u, PROTO_CLOUDFRONT, 26}, /* 180.163.57.128/26 */
    {0xb4a339c0u, PROTO_UNKNOWN, 0},
    {0xb4de6c00u, PROTO_YAHOO, 23}, /* 180.222.108.0/23 */
    {0xb4de6e00u, PROTO_YAHOO, 24}, /* 180.222.110.0/24 */
    {0xb4de6f00u, PROTO_UNKNOWN, 0},
    {0xb6160000u, PROTO_YAHOO, 17}, /* 182.22.0.0/17 */
    {0xb6168000u, PROTO_UNKNOWN, 0},
    {0xb6180000u, PROTO_AWS, 14}, /* 182.24.0.0/14 */
    {0xb61c0000u, PROTO_AWS, 15}, /* 182.28.0.0/15 */
    {0xb61e0000u, PROTO_AWS, 16}, /* 182.30.0.0/16 */
    {0xb61f0000u, PROTO_UNKNOWN, 0},
    {0xb6a14c00u, PROTO_YAHOO, 22}, /* 182.161.76.0/22 */
    {0xb6a14d00u, PROTO_YAHOO, 24}, /* 182.161.77.0/24 */
    {0xb6a15000u, PROTO_UNKNOWN, 0},
    {0xb74f0000u, PROTO_YAHOO, 16}, /* 183.79.0.0/16 */
    {0xb7500000u, PROTO_UNKNOWN, 0},
    {0xb7b14c00u, PROTO_YAHOO, 22}, /* 183.177.76.0/22 */
    {0xb7b15000u, PROTO_YAHOO, 23}, /* 183.177.80.0/23 */
    {0xb7b15400u, PROTO_UNKNOWN, 0},
    {0xb8200000u, PROTO_AWS, 12}, /* 184.32.0.0/12 */
    {0xb8300000u, PROTO_UNKNOWN, 0},
    {0xb8480000u, PROTO_AWS, 15}, /* 184.72.0.0/15 */
    {0xb84a0000u, PROTO_UNKNOWN, 0},
    {0xb84c0000u, PROTO_AWS, 14}, /* 184.76.0.0/14 */
    {0xb8500000u, PROTO_UNKNOWN, 0},
    {0xb8a50000u, PROTO_YAHOO, 16}, /* 184.165.0.0/16 */
    {0xb8a60000u, PROTO_UNKNOWN, 0},
    {0xb8a98000u, PROTO_AWS, 17}, /* 184.169.128.0/17 */
    {0xb8aa0000u, PROTO_UNKNOWN, 0},
    {0xb8c00000u, PROTO_AWS, 11}, /* 184.192.0.0/11 */
    {0xb8e00000u, PROTO_UNKNOWN, 0},
    {0xb902dc00u, PROTO_NETFLIX, 22}, /* 185.2.220.0/22 */
    {0xb902dd00u, PROTO_NETFLIX, 24}, /* 185.2.221.0/24 */
    {0xb902de00u, PROTO_NETFLIX, 22}, /* 185.2.220.0/22 */
    {0xb902e000u, PROTO_UNKNOWN, 0},
    {0xb909bc00u, PROTO_NETFLIX, 22}, /* 185.9.188.0/22 */
    {0xb909c000u, PROTO_UNKNOWN, 0},
    {0xb91f1000u, PROTO_FASTLY, 22}, /* 185.31.16.0/22 */
    {0xb91f1400u, PROTO_UNKNOWN, 0},
    {0xb92acc00u, PROTO_AWS, 22}, /* 185.42.204.0/22 */
    {0xb92ad000u, PROTO_UNKNOWN, 0},
    {0xb92d0400u, PROTO_TWITTER, 24}, /* 185.45.4.0/24 */
    {0xb92d0600u, PROTO_TWITTER, 23}, /* 185.45.6.0/23 */
    {0xb92d0800u, PROTO_UNKNOWN, 0},
    {0xb9307800u, PROTO_AWS, 22}, /* 185.48.120.0/22 */
    {0xb9307c00u, PROTO_UNKNOWN, 0},
    {0xb93cd800u, PROTO_FACEBOOK, 22}, /* 185.60.216.0/22 */
    {0xb93cd900u, PROTO_FACEBOOK, 24}, /* 185.60.217.0/24 */
    {0xb93cdc00u, PROTO_UNKNOWN, 0},
    {0xb93ed800u, PROTO_YAHOO, 22}, /* 185.62.216.0/22 */
    {0xb93ed900u, PROTO_YAHOO, 24}, /* 185.62.217.0/24 */
    {0xb93eda00u, PROTO_YAHOO, 23}, /* 185.62.218.0/23 */
    {0xb93edb00u, PROTO_YAHOO, 24}, /* 185.62.219.0/24 */
    {0xb93edc00u, PROTO_UNKNOWN, 0},
    {0xb98f1000u, PROTO_AWS, 24}, /* 185.143.16.0/24 */
    {0xb98f1100u, PROTO_UNKNOWN, 0},
    {0xb9969400u, PROTO_GOOGLE, 22}, /* 185.150.148.0/22 */
    {0xb9969800u, PROTO_UNKNOWN, 0},
    {0xbaf20000u, PROTO_GOOGLE_CLOUD, 18}, /* 186.242.0.0/18 */
    {0xbaf24000u, PROTO_GOOGLE, 18}, /* 186.242.64.0/18 */
    {0xbaf28000u, PROTO_UNKNOWN, 0},
    {0xbaf50000u, PROTO_GOOGLE, 16}, /* 186.245.0.0/16 */
    {0xbaf60000u, PROTO_UNKNOWN, 0},
    {0xbb4e0000u, PROTO_GOOGLE, 17}, /* 187.78.0.0/17 */
    {0xbb4e8000u, PROTO_UNKNOWN, 0},
    {0xbb4f0000u, PROTO_GOOGLE, 17}, /* 187.79.0.0/17 */
    {0xbb4f8000u, PROTO_UNKNOWN, 0},
    {0xbb7e8000u, PROTO_GOOGLE, 17}, /* 187.126.128.0/17 */
    {0xbb7f0000u, PROTO_UNKNOWN, 0},
    {0xbc40e000u, PROTO_TWITTER, 24}, /* 188.64.224.0/24 */
    {0xbc40e800u, PROTO_UNKNOWN, 0},
    {0xbc726000u, PROTO_CLOUDFLARE, 20}, /* 188.114.96.0/20 */
    {0xbc727000u, PROTO_UNKNOWN, 0},
    {0xbc7d4000u, PROTO_YAHOO, 21}, /* 188.125.64.0/21 */
    {0xbc7d4800u, PROTO_UNKNOWN, 0},
    {0xbc7d5000u, PROTO_YAHOO, 21}, /* 188.125.80.0/21 */
    {0xbc7d5800u, PROTO_UNKNOWN, 0},
    {0xbc7d5c00u, PROTO_YAHOO, 24}, /* 188.125.92.0/24 */
    {0xbc7d5e00u, PROTO_UNKNOWN, 0},
    {0xbd188000u, PROTO_GOOGLE, 17}, /* 189.24.128.0/17 */
    {0xbd190000u, PROTO_UNKNOWN, 0},
    {0xbd300000u, PROTO_GOOGLE, 16}, /* 189.48.0.0/16 */
    {0xbd310000u, PROTO_UNKNOWN, 0},
    {0xbd318000u, PROTO_GOOGLE, 17}, /* 189.49.128.0/17 */
    {0xbd320000u, PROTO_UNKNOWN, 0},
    {0xbd460000u, PROTO_GOOGLE, 15}, /* 189.70.0.0/15 */
    {0xbd480000u, PROTO_UNKNOWN, 0},
    {0xbd520000u, PROTO_GOOGLE, 15}, /* 189.82.0.0/15 */
    {0xbd540000u, PROTO_UNKNOWN, 0},
    {0xbd698000u, PROTO_GOOGLE, 17}, /* 189.105.128.0/17 */
    {0xbd6a0000u, PROTO_GOOGLE, 15}, /* 189.106.0.0/15 */
    {0xbd6c0000u, PROTO_UNKNOWN, 0},
    {0xbe5df000u, PROTO_CLOUDFLARE, 20}, /* 190.93.240.0/20 */
    {0xbe5e0000u, PROTO_UNKNOWN, 0},
    {0xbf008000u, PROTO_GOOGLE, 17}, /* 191.0.128.0/17 */
    {0xbf010000u, PROTO_UNKNOWN, 0},
    {0xbf020000u, PROTO_GOOGLE, 15}, /* 191.2.0.0/15 */
    {0xbf040000u, PROTO_UNKNOWN, 0},
    {0xbf288000u, PROTO_GOOGLE, 17}, /* 191.40.128.0/17 */
    {0xbf290000u, PROTO_UNKNOWN, 0},
    {0xbf2c8000u, PROTO_GOOGLE, 17}, /* 191.44.128.0/17 */
    {0xbf2d0000u, PROTO_UNKNOWN, 0},
    {0xbf2d8000u, PROTO_GOOGLE, 17}, /* 191.45.128.0/17 */
    {0xbf2e0000u, PROTO_GOOGLE, 15}, /* 191.46.0.0/15 */
    {0xbf300000u, PROTO_UNKNOWN, 0},
    {0xbfa60000u, PROTO_AWS, 16}, /* 191.166.0.0/16 */
    {0xbfa70000u, PROTO_UNKNOWN, 0},
    {0xbfd40000u, PROTO_GOOGLE, 15}, /* 191.212.0.0/15 */
    {0xbfd60000u, PROTO_UNKNOWN, 0},
    {0xbfd88000u, PROTO_GOOGLE, 17}, /* 191.216.128.0/17 */
    {0xbfd90000u, PROTO_UNKNOWN, 0},
    {0xbfda0000u, PROTO_GOOGLE, 17}, /* 191.218.0.0/17 */
    {0xbfda8000u, PROTO_UNKNOWN, 0},
    {0xbfdc0000u, PROTO_GOOGLE, 15}, /* 191.220.0.0/15 */
    {0xbfde0000u, PROTO_UNKNOWN, 0},
    {0xbfe81000u, PROTO_AZURE, 21}, /* 191.232.16.0/21 */
    {0xbfe81800u, PROTO_UNKNOWN, 0},
    {0xbfe82000u, PROTO_AZURE, 19}, /* 191.232.32.0/19 */
    {0xbfe84000u, PROTO_AZURE, 20}, /* 191.232.64.0/20 */
    {0xbfe85000u, PROTO_UNKNOWN, 0},
    {0xbfe8a000u, PROTO_AZURE, 19}, /* 191.232.160.0/19 */
    {0xbfe8c000u, PROTO_AZURE, 18}, /* 191.232.192.0/18 */
    {0xbfe90000u, PROTO_AZURE, 19}, /* 191.233.0.0/19 */
    {0xbfe92000u, PROTO_AZURE, 20}, /* 191.233.32.0/20 */
    {0xbfe93000u, PROTO_AZURE, 21}, /* 191.233.48.0/21 */
    {0xbfe93800u, PROTO_UNKNOWN, 0},
    {0xbfe94000u, PROTO_AZURE, 18}, /* 191.233.64.0/18 */
    {0xbfe98000u, PROTO_AZURE, 17}, /* 191.233.128.0/17 */
    {0xbfea0000u, PROTO_UNKNOWN, 0},
    {0xbfea0200u, PROTO_AZURE, 23}, /* 191.234.2.0/23 */
    {0xbfea0400u, PROTO_UNKNOWN, 0},
    {0xbfea1000u, PROTO_AZURE, 20}, /* 191.234.16.0/20 */
    {0xbfea2000u, PROTO_AZURE, 19}, /* 191.234.32.0/19 */
    {0xbfea4000u, PROTO_UNKNOWN, 0},
    {0xbfea8000u, PROTO_AZURE, 17}, /* 191.234.128.0/17 */
    {0xbfeb0000u, PROTO_UNKNOWN, 0},
    {0xbfeb2000u, PROTO_AZURE, 19}, /* 191.235.32.0/19 */
    {0xbfeb4000u, PROTO_AZURE, 18}, /* 191.235.64.0/18 */
    {0xbfeb8000u, PROTO_AZURE, 17}, /* 191.235.128.0/17 */
    {0xbfec0000u, PROTO_AZURE, 16}, /* 191.236.0.0/16 */
    {0xbfed0000u, PROTO_AZURE, 17}, /* 191.237.0.0/17 */
    {0xbfed8000u, PROTO_AZURE, 18}, /* 191.237.128.0/18 */
    {0xbfedc000u, PROTO_AZURE, 22}, /* 191.237.192.0/22 */
    {0xbfedc400u, PROTO_AZURE, 24}, /* 191.237.196.0/24 */
    {0xbfedc500u, PROTO_UNKNOWN, 0},
    {0xbfedc800u, PROTO_AZURE, 21}, /* 191.237.200.0/21 */
    {0xbfedd000u, PROTO_AZURE, 20}, /* 191.237.208.0/20 */
    {0xbfede000u, PROTO_AZURE, 21}, /* 191.237.224.0/21 */
    {0xbfede800u, PROTO_AZURE, 22}, /* 191.237.232.0/22 */
    {0xbfedec00u, PROTO_AZURE, 24}, /* 191.237.236.0/24 */
    {0xbfeded00u, PROTO_UNKNOWN, 0},
    {0xbfedee00u, PROTO_AZURE, 24}, /* 191.237.238.0/24 */
    {0xbfedef00u, PROTO_UNKNOWN, 0},
    {0xbfedf000u, PROTO_AZURE, 23}, /* 191.237.240.0/23 */
    {0xbfedf200u, PROTO_UNKNOWN, 0},
    {0xbfedf800u, PROTO_AZURE, 21}, /* 191.237.248.0/21 */
    {0xbfee0000u, PROTO_AZURE, 18}, /* 191.238.0.0/18 */
    {0xbfee4000u, PROTO_AZURE, 22}, /* 191.238.64.0/22 */
    {0xbfee4400u, PROTO_AZURE, 24}, /* 191.238.68.0/24 */
    {0xbfee4500u, PROTO_UNKNOWN, 0},
    {0xbfee4600u, PROTO_AZURE, 23}, /* 191.238.70.0/23 */
    {0xbfee4800u, PROTO_AZURE, 21}, /* 191.238.72.0/21 */
    {0xbfee5800u, PROTO_AZURE, 22}, /* 191.238.88.0/22 */
    {0xbfee5c00u, PROTO_AZURE, 23}, /* 191.238.92.0/23 */
    {0xbfee5e00u, PROTO_UNKNOWN, 0},
    {0xbfee6000u, PROTO_AZURE, 19}, /* 191.238.96.0/19 */
    {0xbfee8000u, PROTO_AZURE, 21}, /* 191.238.128.0/21 */
    {0xbfee8800u, PROTO_UNKNOWN, 0},
    {0xbfee9000u, PROTO_AZURE, 20}, /* 191.238.144.0/20 */
    {0xbfeea000u, PROTO_AZURE, 19}, /* 191.238.160.0/19 */
    {0xbfeec000u, PROTO_AZURE, 18}, /* 191.238.192.0/18 */
    {0xbfef0000u, PROTO_AZURE, 17}, /* 191.239.0.0/17 */
    {0xbfef8000u, PROTO_UNKNOWN, 0},
    {0xbfefa000u, PROTO_AZURE, 19}, /* 191.239.160.0/19 */
    {0xbfefc000u, PROTO_AZURE, 22}, /* 191.239.192.0/22 */
    {0xbfefc400u, PROTO_UNKNOWN, 0},
    {0xbfefc800u, PROTO_AZURE, 21}, /* 191.239.200.0/21 */
    {0xbfefd000u, PROTO_AZURE, 20}, /* 191.239.208.0/20 */
    {0xbfefe000u, PROTO_AZURE, 19}, /* 191.239.224.0/19 */
    {0xbff00000u, PROTO_UNKNOWN, 0},
    {0xc00c4a00u, PROTO_APPLE, 24}, /* 192.12.74.0/24 */
    {0xc00c4b00u, PROTO_UNKNOWN, 0},
    {0xc0104000u, PROTO_AWS, 21}, /* 192.16.64.0/21 */
    {0xc0104800u, PROTO_UNKNOWN, 0},
    {0xc01fd400u, PROTO_AWS, 23}, /* 192.31.212.0/23 */
    {0xc01fd600u, PROTO_UNKNOWN, 0},
    {0xc0233200u, PROTO_APPLE, 24}, /* 192.35.50.0/24 */
    {0xc0233300u, PROTO_UNKNOWN, 0},
    {0xc02af900u, PROTO_APPLE, 24}, /* 192.42.249.0/24 */
    {0xc02afa00u, PROTO_UNKNOWN, 0},
    {0xc02baf00u, PROTO_AWS, 24}, /* 192.43.175.0/24 */
    {0xc02bb000u, PROTO_UNKNOWN, 0},
    {0xc02bb800u, PROTO_AWS, 24}, /* 192.43.184.0/24 */
    {0xc02bb900u, PROTO_UNKNOWN, 0},
    {0xc02c4400u, PROTO_TWITTER, 23}, /* 192.44.68.0/23 */
    {0xc02c4500u, PROTO_TWITTER, 24}, /* 192.44.69.0/24 */
    {0xc02c4600u, PROTO_UNKNOWN, 0},
    {0xc030ec00u, PROTO_TWITTER, 23}, /* 192.48.236.0/23 */
    {0xc030ee00u, PROTO_UNKNOWN, 0},
    {0xc068a000u, PROTO_GOOGLE, 23}, /* 192.104.160.0/23 */
    {0xc068a200u, PROTO_UNKNOWN, 0},
    {0xc06cef00u, PROTO_AWS, 24}, /* 192.108.239.0/24 */
    {0xc06cf000u, PROTO_UNKNOWN, 0},
    {0xc0854c00u, PROTO_TWITTER, 22}, /* 192.133.76.0/22 */
    {0xc0854e00u, PROTO_TWITTER, 23}, /* 192.133.78.0/23 */
    {0xc0855000u, PROTO_UNKNOWN, 0},
    {0xc09d2400u, PROTO_AWS, 24}, /* 192.157.36.0/24 */
    {0xc09d2500u, PROTO_UNKNOWN, 0},
    {0xc09d4800u, PROTO_AWS, 23}, /* 192.157.72.0/23 */
    {0xc09d4a00u, PROTO_UNKNOWN, 0},
    {0xc09e1c00u, PROTO_GOOGLE_CLOUD, 22}, /* 192.158.28.0/22 */
    {0xc09e2000u, PROTO_UNKNOWN, 0},
    {0xc0ad4000u, PROTO_NETFLIX, 18}, /* 192.173.64.0/18 */
    {0xc0ad8000u, PROTO_UNKNOWN, 0},
    {0xc0b20000u, PROTO_GOOGLE, 15}, /* 192.178.0.0/15 */
    {0xc0b40000u, PROTO_UNKNOWN, 0},
    {0xc0bdc500u, PROTO_AWS, 24}, /* 192.189.197.0/24 */
    {0xc0bdc600u, PROTO_UNKNOWN, 0},
    {0xc0da0800u, PROTO_YAHOO, 21}, /* 192.218.8.0/21 */
    {0xc0da1000u, PROTO_UNKNOWN, 0},
    {0xc0da8800u, PROTO_YAHOO, 23}, /* 192.218.136.0/23 */
    {0xc0da8a00u, PROTO_UNKNOWN, 0},
    {0xc15dc400u, PROTO_YAHOO, 24}, /* 193.93.196.0/24 */
    {0xc15dc800u, PROTO_UNKNOWN, 0},
    {0xc1954000u, PROTO_AZURE, 19}, /* 193.149.64.0/19 */
    {0xc1956000u, PROTO_UNKNOWN, 0},
    {0xc1ba0400u, PROTO_GOOGLE, 24}, /* 193.186.4.0/24 */
    {0xc1ba0500u, PROTO_UNKNOWN, 0},
    {0xc3110000u, PROTO_AWS, 24}, /* 195.17.0.0/24 */
    {0xc3110100u, PROTO_UNKNOWN, 0},
    {0xc3325800u, PROTO_YAHOO, 24}, /* 195.50.88.0/24 */
    {0xc3325900u, PROTO_UNKNOWN, 0},
    {0xc5eaf000u, PROTO_CLOUDFLARE, 22}, /* 197.234.240.0/22 */
    {0xc5eaf400u, PROTO_UNKNOWN, 0},
    {0xc6266000u, PROTO_NETFLIX, 19}, /* 198.38.96.0/19 */
    {0xc6267400u, PROTO_NETFLIX, 24}, /* 198.38.116.0/24 */
    {0xc6267a00u, PROTO_NETFLIX, 19}, /* 198.38.96.0/19 */
    {0xc6268000u, PROTO_UNKNOWN, 0},
    {0xc6296000u, PROTO_AWS, 21}, /* 198.41.96.0/21 */
    {0xc6296800u, PROTO_AWS, 22}, /* 198.41.104.0/22 */
    {0xc6296c00u, PROTO_UNKNOWN, 0},
    {0xc6298000u, PROTO_CLOUDFLARE, 17}, /* 198.41.128.0/17 */
    {0xc62a0000u, PROTO_UNKNOWN, 0},
    {0xc62d3000u, PROTO_NETFLIX, 20}, /* 198.45.48.0/20 */
    {0xc62d4000u, PROTO_UNKNOWN, 0},
    {0xc6630200u, PROTO_AWS, 24}, /* 198.99.2.0/24 */
    {0xc6630300u, PROTO_UNKNOWN, 0},
    {0xc6b46100u, PROTO_AZURE, 25}, /* 198.180.97.0/25 */
    {0xc6b46180u, PROTO_AZURE, 26}, /* 198.180.97.128/26 */
    {0xc6b461c0u, PROTO_AZURE, 27}, /* 198.180.97.192/27 */
    {0xc6b461e0u, PROTO_AZURE, 30}, /* 198.180.97.224/30 */
    {0xc6b461e4u, PROTO_AZURE, 31}, /* 198.180.97.228/31 */
    {0xc6b461e6u, PROTO_UNKNOWN, 0},
    {0xc6b71000u, PROTO_APPLE, 24}, /* 198.183.16.0/24 */
    {0xc6b71200u, PROTO_UNKNOWN, 0},
    {0xc6b71c00u, PROTO_APPLE, 22}, /* 198.183.28.0/22 */
    {0xc6b72000u, PROTO_UNKNOWN, 0},
    {0xc6b78600u, PROTO_YAHOO, 23}, /* 198.183.134.0/23 */
    {0xc6b78a00u, PROTO_UNKNOWN, 0},
    {0xc709f800u, PROTO_AWS, 21}, /* 199.9.248.0/21 */
    {0xc70a0000u, PROTO_UNKNOWN, 0},
    {0xc7109c00u, PROTO_TWITTER, 22}, /* 199.16.156.0/22 */
    {0xc710a000u, PROTO_UNKNOWN, 0},
    {0xc71b4800u, PROTO_FASTLY, 21}, /* 199.27.72.0/21 */
    {0xc71b5000u, PROTO_UNKNOWN, 0},
    {0xc71e1000u, PROTO_AZURE, 24}, /* 199.30.16.0/24 */
    {0xc71e1100u, PROTO_UNKNOWN, 0},
    {0xc71e1200u, PROTO_AZURE, 23}, /* 199.30.18.0/23 */
    {0xc71e1400u, PROTO_AZURE, 24}, /* 199.30.20.0/24 */
    {0xc71e1500u, PROTO_UNKNOWN, 0},
    {0xc71e1600u, PROTO_AZURE, 24}, /* 199.30.22.0/24 */
    {0xc71e1700u, PROTO_UNKNOWN, 0},
    {0xc71e1800u, PROTO_AZURE, 23}, /* 199.30.24.0/23 */
    {0xc71e1a00u, PROTO_UNKNOWN, 0},
    {0xc71e1b00u, PROTO_AZURE, 24}, /* 199.30.27.0/24 */
    {0xc71e1c00u, PROTO_AZURE, 23}, /* 199.30.28.0/23 */
    {0xc71e1e00u, PROTO_UNKNOWN, 0},
    {0xc71e1f00u, PROTO_AZURE, 24}, /* 199.30.31.0/24 */
    {0xc71e2000u, PROTO_UNKNOWN, 0},
    {0xc7249a00u, PROTO_GOOGLE, 23}, /* 199.36.154.0/23 */
    {0xc7249c00u, PROTO_GOOGLE, 24}, /* 199.36.156.0/24 */
    {0xc7249d00u, PROTO_UNKNOWN, 0},
    {0xc73b9400u, PROTO_TWITTER, 22}, /* 199.59.148.0/22 */
    {0xc73b9800u, PROTO_UNKNOWN, 0},
    {0xc7453a00u, PROTO_TWITTER, 23}, /* 199.69.58.0/23 */
    {0xc7453c00u, PROTO_UNKNOWN, 0},
    {0xc7603800u, PROTO_TWITTER, 21}, /* 199.96.56.0/21 */
    {0xc7603900u, PROTO_TWITTER, 24}, /* 199.96.57.0/24 */
    {0xc7603c00u, PROTO_TWITTER, 23}, /* 199.96.60.0/23 */
    {0xc7603f00u, PROTO_TWITTER, 24}, /* 199.96.63.0/24 */
    {0xc7604000u, PROTO_UNKNOWN, 0},
    {0xc77fe800u, PROTO_AWS, 22}, /* 199.127.232.0/22 */
    {0xc77fec00u, PROTO_UNKNOWN, 0},
    {0xc7aa3800u, PROTO_APPLE, 21}, /* 199.170.56.0/21 */
    {0xc7aa4000u, PROTO_UNKNOWN, 0},
    {0xc7c07000u, PROTO_GOOGLE, 23}, /* 199.192.112.0/23 */
    {0xc7c07200u, PROTO_GOOGLE, 24}, /* 199.192.114.0/24 */
    {0xc7c07300u, PROTO_GOOGLE_CLOUD, 24}, /* 199.192.115.0/24 */
    {0xc7c07400u, PROTO_UNKNOWN, 0},
    {0xc7c94000u, PROTO_FACEBOOK, 24}, /* 199.201.64.0/24 */
    {0xc7c94400u, PROTO_UNKNOWN, 0},
    {0xc7dfe800u, PROTO_GOOGLE_CLOUD, 22}, /* 199.223.232.0/22 */
    {0xc7dfec00u, PROTO_GOOGLE_CLOUD, 24}, /* 199.223.236.0/24 */
    {0xc7dfed00u, PROTO_GOOGLE, 24}, /* 199.223.237.0/24 */
    {0xc7dfee00u, PROTO_GOOGLE, 23}, /* 199.223.238.0/23 */
    {0xc7dff000u, PROTO_UNKNOWN, 0},
    {0xc7e80000u, PROTO_FASTLY, 16}, /* 199.232.0.0/16 */
    {0xc7e90000u, PROTO_UNKNOWN, 0},
    {0xc898a000u, PROTO_YAHOO, 23}, /* 200.152.160.0/23 */
    {0xc898a400u, PROTO_UNKNOWN, 0},
    {0xc898a800u, PROTO_YAHOO, 21}, /* 200.152.168.0/21 */
    {0xc898b000u, PROTO_UNKNOWN, 0},
    {0xc8e20000u, PROTO_GOOGLE, 16}, /* 200.226.0.0/16 */
    {0xc8e30000u, PROTO_UNKNOWN, 0},
    {0xca04a400u, PROTO_YAHOO, 24}, /* 202.4.164.0/24 */
    {0xca04a500u, PROTO_UNKNOWN, 0},
    {0xca09d000u, PROTO_YAHOO, 23}, /* 202.9.208.0/23 */
    {0xca09d200u, PROTO_UNKNOWN, 0},
    {0xca12f400u, PROTO_YAHOO, 22}, /* 202.18.244.0/22 */
    {0xca12f800u, PROTO_UNKNOWN, 0},
    {0xca2e1300u, PROTO_YAHOO, 24}, /* 202.46.19.0/24 */
    {0xca2e1400u, PROTO_UNKNOWN, 0},
    {0xca2f8f00u, PROTO_YAHOO, 24}, /* 202.47.143.0/24 */
    {0xca2f9000u, PROTO_UNKNOWN, 0},
    {0xca3a0100u, PROTO_YAHOO, 24}, /* 202.58.1.0/24 */
    {0xca3a0200u, PROTO_UNKNOWN, 0},
    {0xca597800u, PROTO_YAHOO, 24}, /* 202.89.120.0/24 */
    {0xca597a00u, PROTO_UNKNOWN, 0},
    {0xca59e940u, PROTO_AZURE, 27}, /* 202.89.233.64/27 */
    {0xca59e960u, PROTO_UNKNOWN, 0},
    {0xca59eb80u, PROTO_AZURE, 25}, /* 202.89.235.128/25 */
    {0xca59ec00u, PROTO_UNKNOWN, 0},
    {0xca5d4000u, PROTO_YAHOO, 19}, /* 202.93.64.0/19 */
    {0xca5d5000u, PROTO_YAHOO, 20}, /* 202.93.80.0/20 */
    {0xca5d6000u, PROTO_UNKNOWN, 0},
    {0xcaa08000u, PROTO_TWITTER, 22}, /* 202.160.128.0/22 */
    {0xcaa08100u, PROTO_TWITTER, 24}, /* 202.160.129.0/24 */
    {0xcaa08400u, PROTO_UNKNOWN, 0},
    {0xcaa0b000u, PROTO_YAHOO, 20}, /* 202.160.176.0/20 */
    {0xcaa0c000u, PROTO_UNKNOWN, 0},
    {0xcaabea00u, PROTO_YAHOO, 24}, /* 202.171.234.0/24 */
    {0xcaabeb00u, PROTO_UNKNOWN, 0},
    {0xcaae8400u, PROTO_AWS, 22}, /* 202.174.132.0/22 */
    {0xcaae8800u, PROTO_UNKNOWN, 0},
    {0xcada0000u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcada0100u, PROTO_YAHOO, 24}, /* 202.218.1.0/24 */
    {0xcada0200u, PROTO_YAHOO, 23}, /* 202.218.2.0/23 */
    {0xcada0400u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcada2000u, PROTO_YAHOO, 22}, /* 202.218.32.0/22 */
    {0xcada2400u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcada3000u, PROTO_YAHOO, 22}, /* 202.218.48.0/22 */
    {0xcada3400u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcada4e00u, PROTO_YAHOO, 23}, /* 202.218.78.0/23 */
    {0xcada5000u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcada6c00u, PROTO_YAHOO, 23}, /* 202.218.108.0/23 */
    {0xcada6e00u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcada7600u, PROTO_YAHOO, 23}, /* 202.218.118.0/23 */
    {0xcada7800u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcada8700u, PROTO_YAHOO, 24}, /* 202.218.135.0/24 */
    {0xcada8800u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcada9800u, PROTO_YAHOO, 21}, /* 202.218.152.0/21 */
    {0xcada9c00u, PROTO_YAHOO, 22}, /* 202.218.156.0/22 */
    {0xcadaa000u, PROTO_YAHOO, 21}, /* 202.218.160.0/21 */
    {0xcadaa400u, PROTO_YAHOO, 22}, /* 202.218.164.0/22 */
    {0xcadaa800u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcadae000u, PROTO_YAHOO, 20}, /* 202.218.224.0/20 */
    {0xcadae900u, PROTO_YAHOO, 24}, /* 202.218.233.0/24 */
    {0xcadaea00u, PROTO_YAHOO, 20}, /* 202.218.224.0/20 */
    {0xcadaf000u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcadafc00u, PROTO_YAHOO, 23}, /* 202.218.252.0/23 */
    {0xcadafe00u, PROTO_YAHOO, 16}, /* 202.218.0.0/16 */
    {0xcadb0000u, PROTO_UNKNOWN, 0},
    {0xcae4c000u, PROTO_YAHOO, 24}, /* 202.228.192.0/24 */
    {0xcae4c100u, PROTO_UNKNOWN, 0},
    {0xcae4c500u, PROTO_YAHOO, 24}, /* 202.228.197.0/24 */
    {0xcae4c600u, PROTO_UNKNOWN, 0},
    {0xcae4cc00u, PROTO_YAHOO, 22}, /* 202.228.204.0/22 */
    {0xcae4d000u, PROTO_UNKNOWN, 0},
    {0xcae4e000u, PROTO_YAHOO, 20}, /* 202.228.224.0/20 */
    {0xcae4e600u, PROTO_YAHOO, 24}, /* 202.228.230.0/24 */
    {0xcae4e700u, PROTO_YAHOO, 20}, /* 202.228.224.0/20 */
    {0xcae4e900u, PROTO_YAHOO, 24}, /* 202.228.233.0/24 */
    {0xcae4ea00u, PROTO_YAHOO, 20}, /* 202.228.224.0/20 */
    {0xcae4f000u, PROTO_UNKNOWN, 0},
    {0xcae60000u, PROTO_YAHOO, 16}, /* 202.230.0.0/16 */
    {0xcae68800u, PROTO_YAHOO, 24}, /* 202.230.136.0/24 */
    {0xcae68900u, PROTO_YAHOO, 16}, /* 202.230.0.0/16 */
    {0xcae68a00u, PROTO_YAHOO, 24}, /* 202.230.138.0/24 */
    {0xcae68b00u, PROTO_YAHOO, 16}, /* 202.230.0.0/16 */
    {0xcae68e00u, PROTO_YAHOO, 24}, /* 202.230.142.0/24 */
    {0xcae69000u, PROTO_YAHOO, 16}, /* 202.230.0.0/16 */
    {0xcae6c800u, PROTO_YAHOO, 22}, /* 202.230.200.0/22 */
    {0xcae6cc00u, PROTO_YAHOO, 23}, /* 202.230.204.0/23 */
    {0xcae6ce00u, PROTO_YAHOO, 16}, /* 202.230.0.0/16 */
    {0xcae70000u, PROTO_UNKNOWN, 0},
    {0xcaea0000u, PROTO_YAHOO, 18}, /* 202.234.0.0/18 */
    {0xcaea2000u, PROTO_YAHOO, 19}, /* 202.234.32.0/19 */
    {0xcaea3500u, PROTO_YAHOO, 24}, /* 202.234.53.0/24 */
    {0xcaea3600u, PROTO_YAHOO, 19}, /* 202.234.32.0/19 */
    {0xcaea4000u, PROTO_UNKNOWN, 0},
    {0xcaea8000u, PROTO_YAHOO, 18}, /* 202.234.128.0/18 */
    {0xcaeaa000u, PROTO_YAHOO, 19}, /* 202.234.160.0/19 */
    {0xcaeac000u, PROTO_UNKNOWN, 0},
    {0xcaecf600u, PROTO_YAHOO, 24}, /* 202.236.246.0/24 */
    {0xcaecf700u, PROTO_UNKNOWN, 0},
    {0xcaef0000u, PROTO_YAHOO, 20}, /* 202.239.0.0/20 */
    {0xcaef2000u, PROTO_YAHOO, 19}, /* 202.239.32.0/19 */
    {0xcaef2600u, PROTO_YAHOO, 24}, /* 202.239.38.0/24 */
    {0xcaef2700u, PROTO_YAHOO, 19}, /* 202.239.32.0/19 */
    {0xcaef2c00u, PROTO_YAHOO, 24}, /* 202.239.44.0/24 */
    {0xcaef3200u, PROTO_YAHOO, 19}, /* 202.239.32.0/19 */
    {0xcaef4000u, PROTO_UNKNOWN, 0},
    {0xcaf1c000u, PROTO_YAHOO, 18}, /* 202.241.192.0/18 */
    {0xcaf20000u, PROTO_UNKNOWN, 0},
    {0xcaf4cf00u, PROTO_YAHOO, 24}, /* 202.244.207.0/24 */
    {0xcaf4d000u, PROTO_UNKNOWN, 0},
    {0xcb0ed400u, PROTO_YAHOO, 24}, /* 203.14.212.0/24 */
    {0xcb0ed500u, PROTO_UNKNOWN, 0},
    {0xcb53dc00u, PROTO_AWS, 22}, /* 203.83.220.0/22 */
    {0xcb53e000u, PROTO_UNKNOWN, 0},
    {0xcb53f800u, PROTO_YAHOO, 23}, /* 203.83.248.0/23 */
    {0xcb53fa00u, PROTO_UNKNOWN, 0},
    {0xcb54c000u, PROTO_YAHOO, 19}, /* 203.84.192.0/19 */
    {0xcb54d000u, PROTO_YAHOO, 23}, /* 203.84.208.0/23 */
    {0xcb54d200u, PROTO_YAHOO, 19}, /* 203.84.192.0/19 */
    {0xcb54d400u, PROTO_YAHOO, 24}, /* 203.84.212.0/24 */
    {0xcb54d600u, PROTO_YAHOO, 19}, /* 203.84.192.0/19 */
    {0xcb54e000u, PROTO_UNKNOWN, 0},
    {0xcb5f1000u, PROTO_YAHOO, 21}, /* 203.95.16.0/21 */
    {0xcb5f1800u, PROTO_UNKNOWN, 0},
    {0xcb6eed00u, PROTO_YAHOO, 24}, /* 203.110.237.0/24 */
    {0xcb6eef00u, PROTO_UNKNOWN, 0},
    {0xcb85a000u, PROTO_KAKAO, 19}, /* 203.133.160.0/19 */
    {0xcb85a800u, PROTO_KAKAO, 24}, /* 203.133.168.0/24 */
    {0xcb85ab80u, PROTO_KAKAO, 25}, /* 203.133.171.128/25 */
    {0xcb85ac00u, PROTO_KAKAO, 19}, /* 203.133.160.0/19 */
    {0xcb85b800u, PROTO_KAKAO, 24}, /* 203.133.184.0/24 */
    {0xcb85c000u, PROTO_UNKNOWN, 0},
    {0xcb890000u, PROTO_YAHOO, 18}, /* 203.137.0.0/18 */
    {0xcb894000u, PROTO_YAHOO, 20}, /* 203.137.64.0/20 */
    {0xcb897000u, PROTO_YAHOO, 21}, /* 203.137.112.0/21 */
    {0xcb897800u, PROTO_UNKNOWN, 0},
    {0xcb89b000u, PROTO_YAHOO, 21}, /* 203.137.176.0/21 */
    {0xcb89c000u, PROTO_YAHOO, 18}, /* 203.137.192.0/18 */
    {0xcb8a0000u, PROTO_UNKNOWN, 0},
    {0xcb8d2000u, PROTO_YAHOO, 20}, /* 203.141.32.0/20 */
    {0xcb8d3000u, PROTO_UNKNOWN, 0},
    {0xcb8d3600u, PROTO_YAHOO, 24}, /* 203.141.54.0/24 */
    {0xcb8d3700u, PROTO_UNKNOWN, 0},
    {0xcb91e000u, PROTO_YAHOO, 19}, /* 203.145.224.0/19 */
    {0xcb920000u, PROTO_UNKNOWN, 0},
    {0xcbb70000u, PROTO_YAHOO, 20}, /* 203.183.0.0/20 */
    {0xcbb70800u, PROTO_YAHOO, 21}, /* 203.183.8.0/21 */
    {0xcbb71400u, PROTO_YAHOO, 22}, /* 203.183.20.0/22 */
    {0xcbb71800u, PROTO_UNKNOWN, 0},
    {0xcbb71e00u, PROTO_YAHOO, 23}, /* 203.183.30.0/23 */
    {0xcbb72000u, PROTO_YAHOO, 21}, /* 203.183.32.0/21 */
    {0xcbb72800u, PROTO_UNKNOWN, 0},
    {0xcbb73400u, PROTO_YAHOO, 22}, /* 203.183.52.0/22 */
    {0xcbb73600u, PROTO_YAHOO, 23}, /* 203.183.54.0/23 */
    {0xcbb73800u, PROTO_YAHOO, 21}, /* 203.183.56.0/21 */
    {0xcbb73c00u, PROTO_YAHOO, 22}, /* 203.183.60.0/22 */
    {0xcbb74000u, PROTO_YAHOO, 19}, /* 203.183.64.0/19 */
    {0xcbb74800u, PROTO_YAHOO, 21}, /* 203.183.72.0/21 */
    {0xcbb75000u, PROTO_YAHOO, 19}, /* 203.183.64.0/19 */
    {0xcbb76000u, PROTO_UNKNOWN, 0},
    {0xcbb77000u, PROTO_YAHOO, 21}, /* 203.183.112.0/21 */
    {0xcbb77400u, PROTO_YAHOO, 22}, /* 203.183.116.0/22 */
    {0xcbb77800u, PROTO_UNKNOWN, 0},
    {0xcbb7c400u, PROTO_YAHOO, 22}, /* 203.183.196.0/22 */
    {0xcbb7c800u, PROTO_YAHOO, 21}, /* 203.183.200.0/21 */
    {0xcbb7d400u, PROTO_YAHOO, 22}, /* 203.183.212.0/22 */
    {0xcbb7dc00u, PROTO_UNKNOWN, 0},
    {0xcbb7e400u, PROTO_YAHOO, 22}, /* 203.183.228.0/22 */
    {0xcbb7e800u, PROTO_UNKNOWN, 0},
    {0xcbb7f000u, PROTO_YAHOO, 20}, /* 203.183.240.0/20 */
    {0xcbb80000u, PROTO_UNKNOWN, 0},
    {0xcbd88000u, PROTO_YAHOO, 19}, /* 203.216.128.0/19 */
    {0xcbd89000u, PROTO_YAHOO, 20}, /* 203.216.144.0/20 */
    {0xcbd8a000u, PROTO_UNKNOWN, 0},
    {0xcbd8e000u, PROTO_YAHOO, 19}, /* 203.216.224.0/19 */
    {0xcbd90000u, PROTO_UNKNOWN, 0},
    {0xcbd9e000u, PROTO_KAKAO, 19}, /* 203.217.224.0/19 */
    {0xcbd9e100u, PROTO_KAKAO, 24}, /* 203.217.225.0/24 */
    {0xcbd9e300u, PROTO_KAKAO, 19}, /* 203.217.224.0/19 */
    {0xcbda0000u, PROTO_UNKNOWN, 0},
    {0xcbeeb400u, PROTO_KAKAO, 24}, /* 203.238.180.0/24 */
    {0xcbeeb500u, PROTO_UNKNOWN, 0},
    {0xcbf6ac00u, PROTO_KAKAO, 24}, /* 203.246.172.0/24 */
    {0xcbf6ad00u, PROTO_UNKNOWN, 0},
    {0xcc0f1400u, PROTO_FACEBOOK, 22}, /* 204.15.20.0/22 */
    {0xcc0f1800u, PROTO_UNKNOWN, 0},
    {0xcc47b100u, PROTO_YAHOO, 24}, /* 204.71.177.0/24 */
    {0xcc47b200u, PROTO_UNKNOWN, 0},
    {0xcc47bc00u, PROTO_YAHOO, 24}, /* 204.71.188.0/24 */
    {0xcc47bd00u, PROTO_UNKNOWN, 0},
    {0xcc47c800u, PROTO_YAHOO, 22}, /* 204.71.200.0/22 */
    {0xcc47cc00u, PROTO_UNKNOWN, 0},
    {0xcc4fb400u, PROTO_AZURE, 24}, /* 204.79.180.0/24 */
    {0xcc4fb500u, PROTO_UNKNOWN, 0},
    {0xcc4fbe00u, PROTO_APPLE, 24}, /* 204.79.190.0/24 */
    {0xcc4fbf00u, PROTO_UNKNOWN, 0},
    {0xcc57b900u, PROTO_AWS, 24}, /* 204.87.185.0/24 */
    {0xcc57ba00u, PROTO_UNKNOWN, 0},
    {0xcc981200u, PROTO_AZURE, 31}, /* 204.152.18.0/31 */
    {0xcc981202u, PROTO_UNKNOWN, 0},
    {0xcc981208u, PROTO_AZURE, 29}, /* 204.152.18.8/29 */
    {0xcc981210u, PROTO_UNKNOWN, 0},
    {0xcc981220u, PROTO_AZURE, 27}, /* 204.152.18.32/27 */
    {0xcc981240u, PROTO_AZURE, 26}, /* 204.152.18.64/26 */
    {0xcc981280u, PROTO_UNKNOWN, 0},
    {0xcc981300u, PROTO_AZURE, 24}, /* 204.152.19.0/24 */
    {0xcc981400u, PROTO_UNKNOWN, 0},
    {0xccb37800u, PROTO_APPLE, 24}, /* 204.179.120.0/24 */
    {0xccb37900u, PROTO_UNKNOWN, 0},
    {0xccec8000u, PROTO_AWS, 17}, /* 204.236.128.0/17 */
    {0xcced0000u, PROTO_UNKNOWN, 0},
    {0xccf6a000u, PROTO_AWS, 22}, /* 204.246.160.0/22 */
    {0xccf6a400u, PROTO_CLOUDFRONT, 22}, /* 204.246.164.0/22 */
    {0xccf6a800u, PROTO_CLOUDFRONT, 21}, /* 204.246.168.0/21 */
    {0xccf6b000u, PROTO_CLOUDFRONT, 20}, /* 204.246.176.0/20 */
    {0xccf6c000u, PROTO_UNKNOWN, 0},
    {0xcd950800u, PROTO_APPLE, 21}, /* 205.149.8.0/21 */
    {0xcd951000u, PROTO_UNKNOWN, 0},
    {0xcdacd400u, PROTO_YAHOO, 22}, /* 205.172.212.0/22 */
    {0xcdacd500u, PROTO_YAHOO, 24}, /* 205.172.213.0/24 */
    {0xcdacd800u, PROTO_UNKNOWN, 0},
    {0xcdb4af00u, PROTO_APPLE, 24}, /* 205.180.175.0/24 */
    {0xcdb4b000u, PROTO_UNKNOWN, 0},
    {0xcdfbc000u, PROTO_AWS, 21}, /* 205.251.192.0/21 */
    {0xcdfbc800u, PROTO_AWS, 23}, /* 205.251.200.0/23 */
    {0xcdfbca00u, PROTO_CLOUDFRONT, 23}, /* 205.251.202.0/23 */
    {0xcdfbcc00u, PROTO_CLOUDFRONT, 22}, /* 205.251.204.0/22 */
    {0xcdfbd000u, PROTO_CLOUDFRONT, 20}, /* 205.251.208.0/20 */
    {0xcdfbe000u, PROTO_UNKNOWN, 0},
    {0xcdfbe100u, PROTO_AWS, 24}, /* 205.251.225.0/24 */
    {0xcdfbe300u, PROTO_UNKNOWN, 0},
    {0xcdfbe400u, PROTO_AWS, 22}, /* 205.251.228.0/22 */
    {0xcdfbe800u, PROTO_AWS, 21}, /* 205.251.232.0/21 */
    {0xcdfbf800u, PROTO_AWS, 24}, /* 205.251.248.0/24 */
    {0xcdfbf900u, PROTO_CLOUDFRONT, 24}, /* 205.251.249.0/24 */
    {0xcdfbfa00u, PROTO_CLOUDFRONT, 23}, /* 205.251.250.0/23 */
    {0xcdfbfe00u, PROTO_CLOUDFRONT, 24}, /* 205.251.254.0/24 */
    {0xcdfbff00u, PROTO_UNKNOWN, 0},
    {0xce030000u, PROTO_YAHOO, 19}, /* 206.3.0.0/19 */
    {0xce032000u, PROTO_UNKNOWN, 0},
    {0xce48d100u, PROTO_AWS, 24}, /* 206.72.209.0/24 */
    {0xce48d200u, PROTO_UNKNOWN, 0},
    {0xceadfa40u, PROTO_YAHOO, 26}, /* 206.173.250.64/26 */
    {0xceadfa80u, PROTO_UNKNOWN, 0},
    {0xcebe2000u, PROTO_YAHOO, 20}, /* 206.190.32.0/20 */
    {0xcebe3000u, PROTO_YAHOO, 21}, /* 206.190.48.0/21 */
    {0xcebe3800u, PROTO_UNKNOWN, 0},
    {0xcf2e0d00u, PROTO_AZURE, 24}, /* 207.46.13.0/24 */
    {0xcf2e0e00u, PROTO_UNKNOWN, 0},
    {0xcf2e3281u, PROTO_AZURE, 32}, /* 207.46.50.129/32 */
    {0xcf2e3282u, PROTO_AZURE, 31}, /* 207.46.50.130/31 */
    {0xcf2e3284u, PROTO_UNKNOWN, 0},
    {0xcf2e328au, PROTO_AZURE, 31}, /* 207.46.50.138/31 */
    {0xcf2e328eu, PROTO_UNKNOWN, 0},
    {0xcf2e3b40u, PROTO_AZURE, 27}, /* 207.46.59.64/27 */
    {0xcf2e3b60u, PROTO_UNKNOWN, 0},
    {0xcf2e3f40u, PROTO_AZURE, 27}, /* 207.46.63.64/27 */
    {0xcf2e3f60u, PROTO_UNKNOWN, 0},
    {0xcf2e3f80u, PROTO_AZURE, 25}, /* 207.46.63.128/25 */
    {0xcf2e4000u, PROTO_UNKNOWN, 0},
    {0xcf2e4800u, PROTO_AZURE, 27}, /* 207.46.72.0/27 */
    {0xcf2e4820u, PROTO_UNKNOWN, 0},
    {0xcf2e4de1u, PROTO_AZURE, 32}, /* 207.46.77.225/32 */
    {0xcf2e4de2u, PROTO_AZURE, 31}, /* 207.46.77.226/31 */
    {0xcf2e4de4u, PROTO_AZURE, 32}, /* 207.46.77.228/32 */
    {0xcf2e4de5u, PROTO_UNKNOWN, 0},
    {0xcf2e5700u, PROTO_AZURE, 24}, /* 207.46.87.0/24 */
    {0xcf2e5800u, PROTO_UNKNOWN, 0},
    {0xcf2e5910u, PROTO_AZURE, 28}, /* 207.46.89.16/28 */
    {0xcf2e5920u, PROTO_UNKNOWN, 0},
    {0xcf2e5f20u, PROTO_AZURE, 27}, /* 207.46.95.32/27 */
    {0xcf2e5f40u, PROTO_UNKNOWN, 0},
    {0xcf2e7e00u, PROTO_AZURE, 24}, /* 207.46.126.0/24 */
    {0xcf2e7f00u, PROTO_UNKNOWN, 0},
    {0xcf2e8000u, PROTO_AZURE, 19}, /* 207.46.128.0/19 */
    {0xcf2ea000u, PROTO_UNKNOWN, 0},
    {0xcf2ec1c0u, PROTO_AZURE, 28}, /* 207.46.193.192/28 */
    {0xcf2ec1d0u, PROTO_UNKNOWN, 0},
    {0xcf2ec860u, PROTO_AZURE, 27}, /* 207.46.200.96/27 */
    {0xcf2ec880u, PROTO_UNKNOWN, 0},
    {0xcf2ec8b0u, PROTO_AZURE, 28}, /* 207.46.200.176/28 */
    {0xcf2ec8c0u, PROTO_UNKNOWN, 0},
    {0xcf2eca80u, PROTO_AZURE, 28}, /* 207.46.202.128/28 */
    {0xcf2eca90u, PROTO_UNKNOWN, 0},
    {0xcf2ecd00u, PROTO_AZURE, 24}, /* 207.46.205.0/24 */
    {0xcf2ece00u, PROTO_UNKNOWN, 0},
    {0xcf2ee000u, PROTO_AZURE, 20}, /* 207.46.224.0/20 */
    {0xcf2ef000u, PROTO_UNKNOWN, 0},
    {0xcf44ae08u, PROTO_AZURE, 29}, /* 207.68.174.8/29 */
    {0xcf44ae10u, PROTO_UNKNOWN, 0},
    {0xcf44ae28u, PROTO_AZURE, 29}, /* 207.68.174.40/29 */
    {0xcf44ae38u, PROTO_UNKNOWN, 0},
    {0xcf44aeb8u, PROTO_AZURE, 29}, /* 207.68.174.184/29 */
    {0xcf44aec0u, PROTO_AZURE, 27}, /* 207.68.174.192/27 */
    {0xcf44aee0u, PROTO_UNKNOWN, 0},
    {0xcf7ee000u, PROTO_YAHOO, 20}, /* 207.126.224.0/20 */
    {0xcf7ef000u, PROTO_UNKNOWN, 0},
    {0xcfaba000u, PROTO_AWS, 19}, /* 207.171.160.0/19 */
    {0xcfabc000u, PROTO_UNKNOWN, 0},
    {0xcfaf0000u, PROTO_GOOGLE_CLOUD, 16}, /* 207.175.0.0/16 */
    {0xcfb00000u, PROTO_UNKNOWN, 0},
    {0xcfb6a000u, PROTO_WEBEX, 19}, /* 207.182.160.0/19 */
    {0xcfb6a100u, PROTO_WEBEX, 24}, /* 207.182.161.0/24 */
    {0xcfb6c000u, PROTO_UNKNOWN, 0},
    {0xcfdfa000u, PROTO_GOOGLE, 20}, /* 207.223.160.0/20 */
    {0xcfdfb000u, PROTO_UNKNOWN, 0},
    {0xd0085100u, PROTO_WEBEX, 24}, /* 208.8.81.0/24 */
    {0xd0085200u, PROTO_UNKNOWN, 0},
    {0xd0419800u, PROTO_GOOGLE, 22}, /* 208.65.152.0/22 */
    {0xd0419c00u, PROTO_UNKNOWN, 0},
    {0xd0434200u, PROTO_YAHOO, 23}, /* 208.67.66.0/23 */
    {0xd0434400u, PROTO_UNKNOWN, 0},
    {0xd0446c00u, PROTO_GOOGLE, 22}, /* 208.68.108.0/22 */
    {0xd0447000u, PROTO_UNKNOWN, 0},
    {0xd0472800u, PROTO_YAHOO, 21}, /* 208.71.40.0/21 */
    {0xd0473000u, PROTO_UNKNOWN, 0},
    {0xd04b4c00u, PROTO_NETFLIX, 22}, /* 208.75.76.0/22 */
    {0xd04b4d00u, PROTO_NETFLIX, 24}, /* 208.75.77.0/24 */
    {0xd04b5000u, PROTO_UNKNOWN, 0},
    {0xd04e8000u, PROTO_AWS, 21}, /* 208.78.128.0/21 */
    {0xd04e8800u, PROTO_UNKNOWN, 0},
    {0xd051bc00u, PROTO_GOOGLE, 22}, /* 208.81.188.0/22 */
    {0xd051c000u, PROTO_UNKNOWN, 0},
    {0xd0565800u, PROTO_AWS, 22}, /* 208.86.88.0/22 */
    {0xd0565c00u, PROTO_UNKNOWN, 0},
    {0xd06e3000u, PROTO_AWS, 20}, /* 208.110.48.0/20 */
    {0xd06e4000u, PROTO_UNKNOWN, 0},
    {0xd075e000u, PROTO_GOOGLE, 19}, /* 208.117.224.0/19 */
    {0xd0760000u, PROTO_UNKNOWN, 0},
    {0xd0b26f00u, PROTO_YAHOO, 24}, /* 208.178.111.0/24 */
    {0xd0b27000u, PROTO_UNKNOWN, 0},
    {0xd101e000u, PROTO_YAHOO, 23}, /* 209.1.224.0/23 */
    {0xd101e200u, PROTO_UNKNOWN, 0},
    {0xd136b000u, PROTO_AWS, 20}, /* 209.54.176.0/20 */
    {0xd136c000u, PROTO_UNKNOWN, 0},
    {0xd149b400u, PROTO_YAHOO, 22}, /* 209.73.180.0/22 */
    {0xd149b800u, PROTO_UNKNOWN, 0},
    {0xd149b900u, PROTO_YAHOO, 24}, /* 209.73.185.0/24 */
    {0xd149bb00u, PROTO_UNKNOWN, 0},
    {0xd149bc00u, PROTO_YAHOO, 23}, /* 209.73.188.0/23 */
    {0xd149c000u, PROTO_UNKNOWN, 0},
    {0xd1558000u, PROTO_GOOGLE, 17}, /* 209.85.128.0/17 */
    {0xd1560000u, PROTO_UNKNOWN, 0},
    {0xd16bb000u, PROTO_GOOGLE, 20}, /* 209.107.176.0/20 */
    {0xd16bc000u, PROTO_UNKNOWN, 0},
    {0xd1833200u, PROTO_YAHOO, 23}, /* 209.131.50.0/23 */
    {0xd1833800u, PROTO_YAHOO, 24}, /* 209.131.56.0/24 */
    {0xd1833a00u, PROTO_UNKNOWN, 0},
    {0xd1833c00u, PROTO_YAHOO, 23}, /* 209.131.60.0/23 */
    {0xd1833e00u, PROTO_YAHOO, 24}, /* 209.131.62.0/24 */
    {0xd1833f00u, PROTO_UNKNOWN, 0},
    {0xd1c5c000u, PROTO_WEBEX, 19}, /* 209.197.192.0/19 */
    {0xd1c5c100u, PROTO_WEBEX, 24}, /* 209.197.193.0/24 */
    {0xd1c5e000u, PROTO_UNKNOWN, 0},
    {0xd1c71000u, PROTO_AZURE, 20}, /* 209.199.16.0/20 */
    {0xd1c73000u, PROTO_UNKNOWN, 0},
    {0xd1c78000u, PROTO_AZURE, 20}, /* 209.199.128.0/20 */
    {0xd1c79000u, PROTO_UNKNOWN, 0},
    {0xd1c8d800u, PROTO_APPLE, 23}, /* 209.200.216.0/23 */
    {0xd1c8da00u, PROTO_UNKNOWN, 0},
    {0xd1e12800u, PROTO_YAHOO, 24}, /* 209.225.40.0/24 */
    {0xd1e12900u, PROTO_UNKNOWN, 0},
    {0xd1f0d400u, PROTO_AZURE, 23}, /* 209.240.212.0/23 */
    {0xd1f0d600u, PROTO_UNKNOWN, 0},
    {0xd1f79e00u, PROTO_YAHOO, 24}, /* 209.247.158.0/24 */
    {0xd1f79f00u, PROTO_UNKNOWN, 0},
    {0xd204c000u, PROTO_WEBEX, 20}, /* 210.4.192.0/20 */
    {0xd204c100u, PROTO_WEBEX, 24}, /* 210.4.193.0/24 */
    {0xd204c800u, PROTO_WEBEX, 22}, /* 210.4.200.0/22 */
    {0xd204c900u, PROTO_WEBEX, 24}, /* 210.4.201.0/24 */
    {0xd204d000u, PROTO_UNKNOWN, 0},
    {0xd267f000u, PROTO_KAKAO, 24}, /* 210.103.240.0/24 */
    {0xd2680000u, PROTO_UNKNOWN, 0},
    {0xd2810000u, PROTO_YAHOO, 16}, /* 210.129.0.0/16 */
    {0xd2811000u, PROTO_YAHOO, 20}, /* 210.129.16.0/20 */
    {0xd2811800u, PROTO_YAHOO, 21}, /* 210.129.24.0/21 */
    {0xd2812000u, PROTO_YAHOO, 16}, /* 210.129.0.0/16 */
    {0xd2813000u, PROTO_YAHOO, 20}, /* 210.129.48.0/20 */
    {0xd2813800u, PROTO_YAHOO, 21}, /* 210.129.56.0/21 */
    {0xd2814000u, PROTO_YAHOO, 16}, /* 210.129.0.0/16 */
    {0xd281b800u, PROTO_YAHOO, 24}, /* 210.129.184.0/24 */
    {0xd281b900u, PROTO_YAHOO, 16}, /* 210.129.0.0/16 */
    {0xd281d100u, PROTO_YAHOO, 24}, /* 210.129.209.0/24 */
    {0xd281d200u, PROTO_YAHOO, 16}, /* 210.129.0.0/16 */
    {0xd2820000u, PROTO_UNKNOWN, 0},
    {0xd28c0000u, PROTO_YAHOO, 16}, /* 210.140.0.0/16 */
    {0xd28c0900u, PROTO_YAHOO, 24}, /* 210.140.9.0/24 */
    {0xd28c0b00u, PROTO_YAHOO, 16}, /* 210.140.0.0/16 */
    {0xd28c2800u, PROTO_YAHOO, 21}, /* 210.140.40.0/21 */
    {0xd28c3800u, PROTO_YAHOO, 16}, /* 210.140.0.0/16 */
    {0xd28c4000u, PROTO_YAHOO, 18}, /* 210.140.64.0/18 */
    {0xd28c6000u, PROTO_YAHOO, 19}, /* 210.140.96.0/19 */
    {0xd28c6d00u, PROTO_YAHOO, 24}, /* 210.140.109.0/24 */
    {0xd28c6e00u, PROTO_YAHOO, 19}, /* 210.140.96.0/19 */
    {0xd28c7000u, PROTO_YAHOO, 20}, /* 210.140.112.0/20 */
    {0xd28c8000u, PROTO_YAHOO, 19}, /* 210.140.128.0/19 */
    {0xd28ca000u, PROTO_YAHOO, 20}, /* 210.140.160.0/20 */
    {0xd28cb000u, PROTO_YAHOO, 16}, /* 210.140.0.0/16 */
    {0xd28cc000u, PROTO_YAHOO, 18}, /* 210.140.192.0/18 */
    {0xd28ce800u, PROTO_YAHOO, 24}, /* 210.140.232.0/24 */
    {0xd28cec00u, PROTO_YAHOO, 18}, /* 210.140.192.0/18 */
    {0xd28d0000u, PROTO_UNKNOWN, 0},
    {0xd2980000u, PROTO_YAHOO, 16}, /* 210.152.0.0/16 */
    {0xd2981000u, PROTO_YAHOO, 22}, /* 210.152.16.0/22 */
    {0xd2981400u, PROTO_YAHOO, 16}, /* 210.152.0.0/16 */
    {0xd2983400u, PROTO_YAHOO, 22}, /* 210.152.52.0/22 */
    {0xd2983800u, PROTO_YAHOO, 16}, /* 210.152.0.0/16 */
    {0xd2984000u, PROTO_YAHOO, 20}, /* 210.152.64.0/20 */
    {0xd2984800u, PROTO_YAHOO, 21}, /* 210.152.72.0/21 */
    {0xd2985000u, PROTO_YAHOO, 16}, /* 210.152.0.0/16 */
    {0xd2988000u, PROTO_YAHOO, 19}, /* 210.152.128.0/19 */
    {0xd298a000u, PROTO_YAHOO, 20}, /* 210.152.160.0/20 */
    {0xd298b000u, PROTO_YAHOO, 16}, /* 210.152.0.0/16 */
    {0xd298d000u, PROTO_YAHOO, 20}, /* 210.152.208.0/20 */
    {0xd298e000u, PROTO_YAHOO, 19}, /* 210.152.224.0/19 */
    {0xd2990000u, PROTO_UNKNOWN, 0},
    {0xd29ca000u, PROTO_YAHOO, 20}, /* 210.156.160.0/20 */
    {0xd29cb000u, PROTO_UNKNOWN, 0},
    {0xd29ec000u, PROTO_YAHOO, 19}, /* 210.158.192.0/19 */
    {0xd29ee000u, PROTO_UNKNOWN, 0},
    {0xd2a80000u, PROTO_YAHOO, 17}, /* 210.168.0.0/17 */
    {0xd2a86000u, PROTO_YAHOO, 19}, /* 210.168.96.0/19 */
    {0xd2a88000u, PROTO_UNKNOWN, 0},
    {0xd2ab2000u, PROTO_YAHOO, 19}, /* 210.171.32.0/19 */
    {0xd2ab4000u, PROTO_UNKNOWN, 0},
    {0xd2ab6000u, PROTO_YAHOO, 19}, /* 210.171.96.0/19 */
    {0xd2ab8000u, PROTO_UNKNOWN, 0},
    {0xd2bd4000u, PROTO_YAHOO, 19}, /* 210.189.64.0/19 */
    {0xd2bd5100u, PROTO_YAHOO, 24}, /* 210.189.81.0/24 */
    {0xd2bd5200u, PROTO_YAHOO, 19}, /* 210.189.64.0/19 */
    {0xd2bd5400u, PROTO_YAHOO, 23}, /* 210.189.84.0/23 */
    {0xd2bd5600u, PROTO_YAHOO, 19}, /* 210.189.64.0/19 */
    {0xd2bd6000u, PROTO_UNKNOWN, 0},
    {0xd2bdd000u, PROTO_YAHOO, 20}, /* 210.189.208.0/20 */
    {0xd2bdd200u, PROTO_YAHOO, 23}, /* 210.189.210.0/23 */
    {0xd2bdd400u, PROTO_YAHOO, 22}, /* 210.189.212.0/22 */
    {0xd2bdd800u, PROTO_YAHOO, 21}, /* 210.189.216.0/21 */
    {0xd2bde000u, PROTO_YAHOO, 19}, /* 210.189.224.0/19 */
    {0xd2be0000u, PROTO_UNKNOWN, 0},
    {0xd2e5e000u, PROTO_YAHOO, 19}, /* 210.229.224.0/19 */
    {0xd2e60000u, PROTO_UNKNOWN, 0},
    {0xd2eb0000u, PROTO_YAHOO, 19}, /* 210.235.0.0/19 */
    {0xd2eb0e00u, PROTO_YAHOO, 24}, /* 210.235.14.0/24 */
    {0xd2eb1000u, PROTO_YAHOO, 19}, /* 210.235.0.0/19 */
    {0xd2eb2000u, PROTO_UNKNOWN, 0},
    {0xd2ece000u, PROTO_YAHOO, 19}, /* 210.236.224.0/19 */
    {0xd2ed0000u, PROTO_UNKNOWN, 0},
    {0xd2ef2000u, PROTO_YAHOO, 19}, /* 210.239.32.0/19 */
    {0xd2ef2100u, PROTO_YAHOO, 24}, /* 210.239.33.0/24 */
    {0xd2ef2200u, PROTO_YAHOO, 19}, /* 210.239.32.0/19 */
    {0xd2ef3d00u, PROTO_YAHOO, 24}, /* 210.239.61.0/24 */
    {0xd2ef3e00u, PROTO_YAHOO, 19}, /* 210.239.32.0/19 */
    {0xd2ef6000u, PROTO_UNKNOWN, 0},
    {0xd2fac000u, PROTO_YAHOO, 19}, /* 210.250.192.0/19 */
    {0xd2fb0000u, PROTO_UNKNOWN, 0},
    {0xd2fc4000u, PROTO_YAHOO, 19}, /* 210.252.64.0/19 */
    {0xd2fc8000u, PROTO_UNKNOWN, 0},
    {0xd302c000u, PROTO_YAHOO, 18}, /* 211.2.192.0/18 */
    {0xd3030000u, PROTO_UNKNOWN, 0},
    {0xd30a0000u, PROTO_YAHOO, 19}, /* 211.10.0.0/19 */
    {0xd30a0a00u, PROTO_YAHOO, 24}, /* 211.10.10.0/24 */
    {0xd30a0b00u, PROTO_YAHOO, 19}, /* 211.10.0.0/19 */
    {0xd30a1100u, PROTO_YAHOO, 24}, /* 211.10.17.0/24 */
    {0xd30a1200u, PROTO_YAHOO, 19}, /* 211.10.0.0/19 */
    {0xd30a2000u, PROTO_UNKNOWN, 0},
    {0xd30de000u, PROTO_YAHOO, 19}, /* 211.13.224.0/19 */
    {0xd30de800u, PROTO_YAHOO, 21}, /* 211.13.232.0/21 */
    {0xd30e0000u, PROTO_UNKNOWN, 0},
    {0xd30e0800u, PROTO_YAHOO, 24}, /* 211.14.8.0/24 */
    {0xd30e0900u, PROTO_UNKNOWN, 0},
    {0xd30e0c00u, PROTO_YAHOO, 22}, /* 211.14.12.0/22 */
    {0xd30e1000u, PROTO_UNKNOWN, 0},
    {0xd30e1400u, PROTO_YAHOO, 22}, /* 211.14.20.0/22 */
    {0xd30e1800u, PROTO_UNKNOWN, 0},
    {0xd30e1a00u, PROTO_YAHOO, 23}, /* 211.14.26.0/23 */
    {0xd30e1e00u, PROTO_UNKNOWN, 0},
    {0xd30e8000u, PROTO_YAHOO, 18}, /* 211.14.128.0/18 */
    {0xd30ea000u, PROTO_YAHOO, 20}, /* 211.14.160.0/20 */
    {0xd30eb000u, PROTO_YAHOO, 18}, /* 211.14.128.0/18 */
    {0xd30ec000u, PROTO_UNKNOWN, 0},
    {0xd3780000u, PROTO_YAHOO, 18}, /* 211.120.0.0/18 */
    {0xd3784000u, PROTO_UNKNOWN, 0},
    {0xd3858000u, PROTO_YAHOO, 20}, /* 211.133.128.0/20 */
    {0xd3858200u, PROTO_YAHOO, 24}, /* 211.133.130.0/24 */
    {0xd3858300u, PROTO_YAHOO, 20}, /* 211.133.128.0/20 */
    {0xd3858400u, PROTO_YAHOO, 24}, /* 211.133.132.0/24 */
    {0xd3858700u, PROTO_YAHOO, 20}, /* 211.133.128.0/20 */
    {0xd3858b00u, PROTO_YAHOO, 24}, /* 211.133.139.0/24 */
    {0xd3858c00u, PROTO_YAHOO, 20}, /* 211.133.128.0/20 */
    {0xd3858f00u, PROTO_YAHOO, 24}, /* 211.133.143.0/24 */
    {0xd3859000u, PROTO_UNKNOWN, 0},
    {0xd385f000u, PROTO_YAHOO, 20}, /* 211.133.240.0/20 */
    {0xd3860000u, PROTO_UNKNOWN, 0},
    {0xd3e76000u, PROTO_KAKAO, 24}, /* 211.231.96.0/24 */
    {0xd3e76800u, PROTO_KAKAO, 21}, /* 211.231.104.0/21 */
    {0xd3e76900u, PROTO_KAKAO, 24}, /* 211.231.105.0/24 */
    {0xd3e77000u, PROTO_UNKNOWN, 0},
    {0xd4526000u, PROTO_YAHOO, 22}, /* 212.82.96.0/22 */
    {0xd4526400u, PROTO_UNKNOWN, 0},
    {0xd4526800u, PROTO_YAHOO, 21}, /* 212.82.104.0/21 */
    {0xd4527000u, PROTO_YAHOO, 20}, /* 212.82.112.0/20 */
    {0xd4527600u, PROTO_YAHOO, 23}, /* 212.82.118.0/23 */
    {0xd4527800u, PROTO_YAHOO, 20}, /* 212.82.112.0/20 */
    {0xd4528000u, PROTO_UNKNOWN, 0},
    {0xd5c78000u, PROTO_AZURE, 20}, /* 213.199.128.0/20 */
    {0xd5c79000u, PROTO_UNKNOWN, 0},
    {0xd5c7a900u, PROTO_AZURE, 24}, /* 213.199.169.0/24 */
    {0xd5c7aa00u, PROTO_UNKNOWN, 0},
    {0xd5c7b420u, PROTO_AZURE, 28}, /* 213.199.180.32/28 */
    {0xd5c7b430u, PROTO_UNKNOWN, 0},
    {0xd5c7b460u, PROTO_AZURE, 27}, /* 213.199.180.96/27 */
    {0xd5c7b480u, PROTO_UNKNOWN, 0},
    {0xd5c7b4c0u, PROTO_AZURE, 27}, /* 213.199.180.192/27 */
    {0xd5c7b4e0u, PROTO_UNKNOWN, 0},
    {0xd5c7b700u, PROTO_AZURE, 24}, /* 213.199.183.0/24 */
    {0xd5c7b800u, PROTO_UNKNOWN, 0},
    {0xd8273000u, PROTO_YAHOO, 20}, /* 216.39.48.0/20 */
    {0xd8274000u, PROTO_UNKNOWN, 0},
    {0xd8278800u, PROTO_AWS, 21}, /* 216.39.136.0/21 */
    {0xd8279000u, PROTO_UNKNOWN, 0},
    {0xd8279800u, PROTO_AWS, 21}, /* 216.39.152.0/21 */
    {0xd827a000u, PROTO_AWS, 20}, /* 216.39.160.0/20 */
    {0xd827b000u, PROTO_UNKNOWN, 0},
    {0xd8304400u, PROTO_YAHOO, 24}, /* 216.48.68.0/24 */
    {0xd8304500u, PROTO_UNKNOWN, 0},
    {0xd83ac000u, PROTO_GOOGLE, 19}, /* 216.58.192.0/19 */
    {0xd83ae000u, PROTO_UNKNOWN, 0},
    {0xd8495000u, PROTO_GOOGLE, 20}, /* 216.73.80.0/20 */
    {0xd8496000u, PROTO_UNKNOWN, 0},
    {0xd86d7000u, PROTO_YAHOO, 22}, /* 216.109.112.0/22 */
    {0xd86d7200u, PROTO_YAHOO, 23}, /* 216.109.114.0/23 */
    {0xd86d7400u, PROTO_UNKNOWN, 0},
    {0xd8736000u, PROTO_YAHOO, 20}, /* 216.115.96.0/20 */
    {0xd8736700u, PROTO_YAHOO, 24}, /* 216.115.103.0/24 */
    {0xd8736800u, PROTO_YAHOO, 20}, /* 216.115.96.0/20 */
    {0xd8737000u, PROTO_UNKNOWN, 0},
    {0xd8888000u, PROTO_YAHOO, 22}, /* 216.136.128.0/22 */
    {0xd8888400u, PROTO_UNKNOWN, 0},
    {0xd888ac00u, PROTO_YAHOO, 22}, /* 216.136.172.0/22 */
    {0xd888b000u, PROTO_UNKNOWN, 0},
    {0xd888cb00u, PROTO_YAHOO, 24}, /* 216.136.203.0/24 */
    {0xd888cd00u, PROTO_UNKNOWN, 0},
    {0xd888dc80u, PROTO_YAHOO, 25}, /* 216.136.220.128/25 */
    {0xd888dd00u, PROTO_UNKNOWN, 0},
    {0xd888e000u, PROTO_YAHOO, 22}, /* 216.136.224.0/22 */
    {0xd888e400u, PROTO_UNKNOWN, 0},
    {0xd888e800u, PROTO_YAHOO, 22}, /* 216.136.232.0/22 */
    {0xd888ec00u, PROTO_UNKNOWN, 0},
    {0xd8892000u, PROTO_CLOUDFRONT, 19}, /* 216.137.32.0/19 */
    {0xd8894000u, PROTO_UNKNOWN, 0},
    {0xd8913000u, PROTO_YAHOO, 20}, /* 216.145.48.0/20 */
    {0xd8914000u, PROTO_UNKNOWN, 0},
    {0xd89bc000u, PROTO_YAHOO, 20}, /* 216.155.192.0/20 */
    {0xd89bd000u, PROTO_UNKNOWN, 0},
    {0xd8b6e000u, PROTO_AWS, 20}, /* 216.182.224.0/20 */
    {0xd8b6f000u, PROTO_UNKNOWN, 0},
    {0xd8c6c000u, PROTO_AWS, 23}, /* 216.198.192.0/23 */
    {0xd8c6c200u, PROTO_AWS, 24}, /* 216.198.194.0/24 */
    {0xd8c6c300u, PROTO_UNKNOWN, 0},
    {0xd8c6c400u, PROTO_AWS, 22}, /* 216.198.196.0/22 */
    {0xd8c6c800u, PROTO_AWS, 21}, /* 216.198.200.0/21 */
    {0xd8c6d000u, PROTO_AWS, 20}, /* 216.198.208.0/20 */
    {0xd8c6e000u, PROTO_AWS, 19}, /* 216.198.224.0/19 */
    {0xd8c70000u, PROTO_UNKNOWN, 0},
    {0xd8d80000u, PROTO_AWS, 15}, /* 216.216.0.0/15 */
    {0xd8da0000u, PROTO_UNKNOWN, 0},
    {0xd8dcd000u, PROTO_AZURE, 20}, /* 216.220.208.0/20 */
    {0xd8dce000u, PROTO_UNKNOWN, 0},
    {0xd8ef2000u, PROTO_GOOGLE, 19}, /* 216.239.32.0/19 */
    {0xd8ef4000u, PROTO_UNKNOWN, 0},
    {0xd8f40000u, PROTO_AWS, 18}, /* 216.244.0.0/18 */
    {0xd8f44000u, PROTO_UNKNOWN, 0},
    {0xd8fc6000u, PROTO_YAHOO, 19}, /* 216.252.96.0/19 */
    {0xd8fc6800u, PROTO_YAHOO, 21}, /* 216.252.104.0/21 */
    {0xd8fc7000u, PROTO_YAHOO, 19}, /* 216.252.96.0/19 */
    {0xd8fc8000u, PROTO_UNKNOWN, 0},
    {0xd8fcdc00u, PROTO_GOOGLE, 22}, /* 216.252.220.0/22 */
    {0xd8fce000u, PROTO_UNKNOWN, 0},
    {0xd8ffe000u, PROTO_YAHOO, 20}, /* 216.255.224.0/20 */
    {0xd8ffe800u, PROTO_YAHOO, 21}, /* 216.255.232.0/21 */
    {0xd8fff000u, PROTO_UNKNOWN, 0},
    {0xd90c0400u, PROTO_YAHOO, 22}, /* 217.12.4.0/22 */
    {0xd90c0e00u, PROTO_YAHOO, 24}, /* 217.12.14.0/24 */
    {0xd90c0f00u, PROTO_YAHOO, 22}, /* 217.12.12.0/22 */
    {0xd90c1000u, PROTO_UNKNOWN, 0},
    {0xd992b000u, PROTO_YAHOO, 21}, /* 217.146.176.0/21 */
    {0xd992c000u, PROTO_UNKNOWN, 0},
    {0xda269000u, PROTO_KAKAO, 24}, /* 218.38.144.0/24 */
    {0xda269100u, PROTO_UNKNOWN, 0},
    {0xdbf9bd00u, PROTO_KAKAO, 24}, /* 219.249.189.0/24 */
    {0xdbf9bf00u, PROTO_UNKNOWN, 0},
    {0xdbf9d500u, PROTO_KAKAO, 24}, /* 219.249.213.0/24 */
    {0xdbf9d600u, PROTO_UNKNOWN, 0},
    {0xdbf9e300u, PROTO_KAKAO, 24}, /* 219.249.227.0/24 */
    {0xdbf9e400u, PROTO_UNKNOWN, 0},
    {0xdbf9e700u, PROTO_KAKAO, 24}, /* 219.249.231.0/24 */
    {0xdbf9e800u, PROTO_UNKNOWN, 0},
    {0xdc473800u, PROTO_KAKAO, 24}, /* 220.71.56.0/24 */
    {0xdc473900u, PROTO_UNKNOWN, 0},
};
