/*
 * File:   http.h
 * Author: montimage
 *
 * Created on 20 septembre 2011, 14:09
 */

#ifndef MMT_NFS_H
#define MMT_NFS_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"


// #define NDN_MAX_EXPIRED_TIME 360 // 360 seconds : Maximum number of time for interestlifetime and freshnessperiod
enum nfs_opcode
{
	NFS_OPCODE_ACCESS = 3,
	NFS_OPCODE_CLOSE = 4,
	NFS_DELEGRETURN = 8,
	NFS_OPCODE_GETATTR = 9,
	NFS_OPCODE_GETFH = 10,
	NFS_OPCODE_LOOKUP = 15,
	NFS_OPCODE_OPEN = 18,
	NFS_OPCODE_OPEN_CONFIRM = 20,
	NFS_OPCODE_PUTFH = 22,
	NFS_OPCODE_READ = 25,
	NFS_OPCODE_READDIR = 26,
	NFS_OPCODE_REMOVE = 28,
	NFS_OPCODE_RENAME = 29,
	NFS_OPCODE_SAVEFH = 32,
	NFS_OPCODE_SETATTR = 34,
	NFS_OPCODE_SETCLIENTID = 35,
	NFS_OPCODE_SETCLIENTID_CONFIRM = 36,
	NFS_OPCODE_WRITE = 38,
};

typedef struct nfs_opcode_struct {
	int opcode;
	int data_offset;
	// struct nfs_opcode_struct * next;
} nfs_opcode_t;

/**
 * Create new nfs_opcode_t struct
 * @return a pointer points to new nfs_opcode_t struct
 *           NULL if cannot allocate memory
 */
nfs_opcode_t * nfs_opcode_new();

/**
 * Free a nfs_opcode_t struct
 * @param nfs_opcode nfs_opcode_t structure to be freed
 */
void nfs_opcode_free(nfs_opcode_t *nfs_opcode);

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_NFS_H */
