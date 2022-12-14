#pragma once

struct AVFormatContext;
struct PayloadContext;
struct AVStream;
struct AVPacket;

struct PayloadContext;

void parse_profile_level_id(AVFormatContext *s,
	PayloadContext *h264_data,
	const char *value);


int h264_handle_packet(AVFormatContext *ctx, PayloadContext *data,
                              AVStream *st, AVPacket *pkt, uint32_t *timestamp,
                              const uint8_t *buf, int len, uint16_t seq,
                              int flags);
