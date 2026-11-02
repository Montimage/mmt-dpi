/*
 * tunnel_walk.h — shared by the encapsulation walkers of issue #572
 * (proto_mpls.c, proto_vxlan.c, proto_geneve.c, proto_pppoe.c, proto_ppp.c).
 */
#ifndef MMT_TCPIP_TUNNEL_WALK_H
#define MMT_TCPIP_TUNNEL_WALK_H

#include <string.h>

#include "mmt_core.h"

/*
 * An encapsulation layer at `index` found no inner layer to hand on (a
 * header cut short of caplen, a control or discovery packet, a stack without
 * a bottom entry). The packet's protocol path is its session's, so the inner
 * layers an earlier packet of the same outer flow appended are still in it
 * and would be processed with that packet's offsets: end the session path
 * here, as GTP does for its non-T-PDU messages (proto_gtp.c), and drop the
 * winning checkers recorded beyond it (issue #252). Returns 0, the
 * classifier's "no next protocol".
 */
static inline int mmt_tunnel_end_path(ipacket_t *ipacket, unsigned index) {
    if (ipacket->session != NULL && index + 1 < PROTO_PATH_SIZE
            && ipacket->session->proto_path.len > (int) index + 1) {
        ipacket->session->proto_path.len = (int) index + 1;
        memset(&ipacket->session->proto_checkers[index + 1], 0,
               (PROTO_PATH_SIZE - index - 1) * sizeof(ipacket->session->proto_checkers[0]));
    }
    return 0;
}

#endif /* MMT_TCPIP_TUNNEL_WALK_H */
