/* vi: set sw=4 ts=4: */
/*
 * OpenSSL 3.x algorithm pruning stubs for static BusyBox builds
 *
 * Eliminates large precomputed curve tables, unneeded standalone hashes,
 * and legacy registration lists:
 * - ecp_sm2p256_table.o (524 KB) via EC_GFp_sm2p256_method stub
 * - sm3.o and sm3_prov.o via ossl_sm3_functions stub
 * - ripemd.o and ripemd_prov.o via ossl_ripemd160_functions stub
 * - c_allc.o and c_alld.o via openssl_add_all_* stubs
 *
 * Licensed under GPLv2 or later.
 */

#include "libbb.h"

/* Anchor to ensure openssl_prune.o is extracted from networking/lib.a */
void openssl_prune_anchor(void);
void openssl_prune_anchor(void)
{
}

/* Generic empty dispatch table */
static const void *const dummy_dispatch[] = { (void *)0, (void *)0 };

/*
 * 1. Stub out SM2 curve method (Chinese GM/T 0003-2012).
 * Eliminates ecp_sm2p256.o and ecp_sm2p256_table.o (524 KB table).
 */
const void *EC_GFp_sm2p256_method(void);
const void *EC_GFp_sm2p256_method(void)
{
	return (void *)0;
}

/*
 * 2. Self-contained hash stubs (never used by ADB TLS / RSA)
 */
const void *const ossl_sm3_functions = dummy_dispatch;
const void *const ossl_ripemd160_functions = dummy_dispatch;

/*
 * 3. Stub out legacy OpenSSL 1.x algorithm registration tables.
 * Eliminates c_allc.o (DES, RC2, RC4, Camellia, ARIA, Blowfish, CAST, IDEA)
 * and c_alld.o (MD4, MD5, RIPEMD160, Whirlpool, SM3, BLAKE2).
 */
void openssl_add_all_ciphers_int(void);
void openssl_add_all_ciphers_int(void)
{
}

void openssl_add_all_digests_int(void);
void openssl_add_all_digests_int(void)
{
}

/*
 * 4. Stub out OpenSSL 3.x QUIC client and server methods.
 * ADB wireless debugging operates exclusively over TLS 1.3 over TCP.
 * Eliminates the entire QUIC engine (quic_method.o, quic_channel.o,
 * quic_txp.o, quic_rx_depack.o, quic_impl.o, quic_tserver.o - ~300 KB).
 */
const void *OSSL_QUIC_client_method(void);
const void *OSSL_QUIC_client_method(void)
{
	return (void *)0;
}

const void *OSSL_QUIC_client_thread_method(void);
const void *OSSL_QUIC_client_thread_method(void)
{
	return (void *)0;
}

const void *OSSL_QUIC_server_method(void);
const void *OSSL_QUIC_server_method(void)
{
	return (void *)0;
}
