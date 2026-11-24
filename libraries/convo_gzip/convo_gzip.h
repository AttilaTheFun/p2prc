#ifndef CONVO_GZIP_H
#define CONVO_GZIP_H

#include <stddef.h>
#include <stdint.h>

// Gzip via the system zlib, replacing Apple's Compression framework for the
// pairing blobs.
//
// Not an aesthetic choice: libcompression's DEFLATE encoder emits match
// distances that reach back as though the 32KB window were pre-seeded.
// Lenient inflates (Safari's, Python's) shrug and read zeros; Chromium's
// strict zlib rejects the whole stream with "invalid distance too far back",
// which surfaced as a phone-made invite that no Chrome tab could open. libz
// produces streams every decoder accepts, and with windowBits 15+16 it writes
// the gzip header and trailer itself.

// Compresses `in` as gzip into `out`. Returns bytes written, or -1 if the
// output buffer is too small or zlib fails.
long convo_gzip_deflate(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap);

// Decompresses gzip (or zlib; the header is auto-detected) into `out`.
// Returns bytes written, or -1 on malformed input or insufficient space.
long convo_gzip_inflate(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap);

#endif
