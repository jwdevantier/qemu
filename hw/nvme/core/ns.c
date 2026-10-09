/*
 * QEMU NVM Express shared namespace identity (core)
 *
 * Default namespace UUID shared by the vnvme (prod) and nvme (test)
 * devices. Both devices derive the same UUID from the same inputs, so
 * a guest sees a consistent namespace identity regardless of which
 * device model backs the namespace, and the identity is stable across
 * boots and migration.
 *
 * This code is covered by the QEMU security policy.
 *
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include "crypto/hash.h"
#include "hw/nvme/core/nvme.h"

/*
 * The derivation is guest-visible ABI; see the comment on
 * nvme_ns_derive_uuid() in core/nvme.h. RFC 4122 version 5 is defined
 * on SHA-1; the digest is not used for any security purpose, only as
 * a stable namespace identity.
 */
void nvme_ns_derive_uuid(const char *idstr, uint32_t nsid, QemuUUID *uuid)
{
    static const QemuUUID ns = {
        .data = { 0xe0, 0x74, 0x6f, 0xe0, 0x2a, 0x28, 0x5b, 0x3a,
                  0x81, 0xff, 0xd3, 0xb3, 0x5c, 0xce, 0x61, 0x01 },
    };
    g_autofree char *name = g_strdup_printf("%s:%u", idstr, nsid);
    struct iovec iov[2] = {
        { .iov_base = (void *)ns.data, .iov_len = sizeof(ns.data), },
        { .iov_base = name,            .iov_len = strlen(name),     },
    };
    uint8_t digest[QCRYPTO_HASH_DIGEST_LEN_SHA1];
    uint8_t *result;
    size_t resultlen;

    if (qcrypto_hash_bytesv(QCRYPTO_HASH_ALGO_SHA1, iov, ARRAY_SIZE(iov),
                            &result, &resultlen, NULL) < 0 ||
        resultlen < sizeof(digest)) {
        memset(uuid->data, 0, sizeof(uuid->data));
        return;
    }

    memcpy(digest, result, sizeof(digest));
    g_free(result);

    memcpy(uuid->data, digest, sizeof(uuid->data));

    /* version 5, RFC 4122 variant */
    uuid->data[6] = (uuid->data[6] & 0x0f) | (5 << 4);
    uuid->data[8] = (uuid->data[8] & 0x3f) | 0x80;
}
