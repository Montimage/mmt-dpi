
#ifndef _MMT_CFG_DEFAULTS_H
#define _MMT_CFG_DEFAULTS_H


/**
 * Limitations for the "opensource" version
 */

#ifdef CFG_OPENSOURCE

/** Packet count limit (def.: 1 million) */

#ifndef CFG_OS_MAX_PACKET
#define CFG_OS_MAX_PACKET (1000 * 1000)
#endif

#endif /*CFG_OPENSOURCE*/


/** The value in seconds of the session expiry for short life applicattions */

#ifndef CFG_CLASSIFICATION_THRESHOLD
#define CFG_CLASSIFICATION_THRESHOLD 20
#endif


/** The value in seconds of the session expiry - https://tools.ietf.org/html/rfc2988*/

#ifndef CFG_DEFAULT_SESSION_TIMEOUT
#define CFG_DEFAULT_SESSION_TIMEOUT 60
#endif


/** The value in seconds of the session expiry for established connections.
	This is reasonable for Web and SSL connections especially when long polling is used.
	Usually applications have a long polling period of about 3~5 minutes. */

#ifndef CFG_SHORT_LIFE_SESSION_TIMEOUT
#define CFG_SHORT_LIFE_SESSION_TIMEOUT 15
#endif


/** The value in seconds of the session expiry for established connections.
	This is reasonable for Web and SSL connections especially when long polling is used.
	Usually applications have a long polling period of about 3~5 minutes. */

#ifndef CFG_LONG_SESSION_TIMEOUT
#define CFG_LONG_SESSION_TIMEOUT 600
#endif


/** The value in seconds of the session expiry for persistant connections like
	messaging applications and so on.
	These applications may have very long sleep time 30minutes is reasonable. */

#ifndef CFG_LIVE_SESSION_TIMEOUT
#define CFG_LIVE_SESSION_TIMEOUT 1500
#endif


#endif /*_MMT_CFG_DEFAULTS_H*/
