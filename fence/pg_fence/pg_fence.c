/*
 * pg_fence: Consequence Fence Protocol (CFP) reference extension, C part.
 * Provides Ed25519 signature verification (libsodium). Everything else is SQL.
 */
#include "postgres.h"
#include "fmgr.h"
#include "varatt.h"
#include <sodium.h>

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_init(void)
{
    if (sodium_init() < 0)
        elog(ERROR, "pg_fence: libsodium initialisation failed");
}

PG_FUNCTION_INFO_V1(fence_ed25519_verify);
Datum
fence_ed25519_verify(PG_FUNCTION_ARGS)
{
    bytea *pk  = PG_GETARG_BYTEA_PP(0);
    bytea *msg = PG_GETARG_BYTEA_PP(1);
    bytea *sig = PG_GETARG_BYTEA_PP(2);

    if (VARSIZE_ANY_EXHDR(pk) != crypto_sign_PUBLICKEYBYTES ||
        VARSIZE_ANY_EXHDR(sig) != crypto_sign_BYTES)
        PG_RETURN_BOOL(false);

    PG_RETURN_BOOL(crypto_sign_verify_detached(
        (const unsigned char *) VARDATA_ANY(sig),
        (const unsigned char *) VARDATA_ANY(msg), VARSIZE_ANY_EXHDR(msg),
        (const unsigned char *) VARDATA_ANY(pk)) == 0);
}
