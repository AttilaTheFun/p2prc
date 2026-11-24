#include "convo_gzip.h"

#include <zlib.h>

// windowBits 15 is the full DEFLATE window; +16 selects gzip framing on
// deflate and requires it on inflate. +32 on inflate additionally accepts
// bare zlib, which costs nothing and forgives a peer that framed differently.

long convo_gzip_deflate(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap) {
    z_stream stream = {0};
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 9,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    stream.next_in = (Bytef *)in;
    stream.avail_in = (uInt)in_len;
    stream.next_out = out;
    stream.avail_out = (uInt)out_cap;
    int status = deflate(&stream, Z_FINISH);
    long written = (long)stream.total_out;
    deflateEnd(&stream);
    return status == Z_STREAM_END ? written : -1;
}

long convo_gzip_inflate(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap) {
    z_stream stream = {0};
    if (inflateInit2(&stream, 15 + 32) != Z_OK) {
        return -1;
    }
    stream.next_in = (Bytef *)in;
    stream.avail_in = (uInt)in_len;
    stream.next_out = out;
    stream.avail_out = (uInt)out_cap;
    int status = inflate(&stream, Z_FINISH);
    long written = (long)stream.total_out;
    inflateEnd(&stream);
    return status == Z_STREAM_END ? written : -1;
}
