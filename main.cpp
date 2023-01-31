/*
 * libdatachannel media receiver example
 * Copyright (c) 2020 Staz Modrzynski
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include "rtc/rtc.hpp"

#include <iostream>
#include <memory>
#include <utility>
#include <fstream>

#include <nlohmann/json.hpp>

extern "C"
{
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
}

#include <opencv2/imgproc/imgproc.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui/highgui.hpp>

#include "fqueue.h"


using nlohmann::json;

inline auto GetSize(const rtc::binary& packet) { return packet.size(); }

struct AVFrameDeleter
{
	void operator()(AVFrame *frame) const { av_frame_free(&frame); };
};

using AVFramePtr = std::unique_ptr<AVFrame, AVFrameDeleter>;


struct VideoQueue
{
	FQueue<rtc::binary, 15 * 1024 * 1024, 500> mQueue;
	rtc::binary mBuffer;
};


int read_raw_packet(void *opaque, uint8_t *buf, int buf_size)
{
	VideoQueue& videoQueue = *static_cast<VideoQueue*>(opaque);

	if (videoQueue.mBuffer.empty())
	{
		if (!videoQueue.mQueue.pop(videoQueue.mBuffer))
			return AVERROR_EOF;
	}

	//while (videoQueue.mBuffer.size() < buf_size)
	//{
	//	rtc::binary buffer;
	//	if (!videoQueue.mQueue.pop(buffer))
	//		return AVERROR_EOF;
	//	videoQueue.mBuffer.insert(videoQueue.mBuffer.end(), buffer.begin(), buffer.end());
	//}

	const int ret_size = std::min((int)videoQueue.mBuffer.size(), buf_size);
	memcpy(buf, videoQueue.mBuffer.data(), ret_size);
	videoQueue.mBuffer.erase(videoQueue.mBuffer.begin(), videoQueue.mBuffer.begin() + ret_size);
	return ret_size;
}

int write_packet(void *opaque, uint8_t *buf, int buf_size)
{
	return 0;
}


int main() {
	try {
		rtc::InitLogger(rtc::LogLevel::Debug);
		auto pc = std::make_shared<rtc::PeerConnection>();

		std::string localDescription;

		pc->onStateChange(
		    [](rtc::PeerConnection::State state) { std::cout << "State: " << state << std::endl; });

		pc->onGatheringStateChange([pc, &localDescription](rtc::PeerConnection::GatheringState state) {
			std::cout << "Gathering State: " << state << std::endl;
			if (state == rtc::PeerConnection::GatheringState::Complete) {
				auto description = pc->localDescription();
				localDescription = std::string(description.value());
				json message = {{"type", description->typeString()},
				                {"sdp", std::string(description.value())}};
				std::cout << message << std::endl;
			}
		});

		VideoQueue videoQueue;

		rtc::Description::Video media("video", rtc::Description::Direction::RecvOnly);
		media.addH264Codec(96);
		media.setBitrate(
		    2500); // Request 3Mbps (Browsers do not encode more than 2.5MBps from a webcam)

		auto track = pc->addTrack(media);

		auto session = std::make_shared<rtc::RtcpReceivingSession>();
		track->setMediaHandler(session);

		track->onMessage(
			[&videoQueue](rtc::binary message) {
				videoQueue.mQueue.push(message);
			},
			[](std::string message) { 
				std::cout << "*** String message: " << message << std::endl;
			});

		pc->setLocalDescription();

		std::cout << "Expect RTP video traffic on localhost:5000" << std::endl;
		std::cout << "Please copy/paste the answer provided by the browser: " << std::endl;
		std::string sdp;
		std::getline(std::cin, sdp);

		std::cout << "Got answer" << sdp << std::endl;
		json j = json::parse(sdp);
		auto sdpClause = j["sdp"].get<std::string>();
		rtc::Description answer(sdpClause, j["type"].get<std::string>());
		pc->setRemoteDescription(answer);

		// https://blog.kevmo314.com/custom-rtp-io-with-ffmpeg.html
		AVInputFormat *file_iformat = av_find_input_format("sdp");
		AVFormatContext *ic = avformat_alloc_context();
		AVDictionary *format_opts = NULL;
		av_dict_set(&format_opts, "sdp_flags", "custom_io", 0);

		//av_dict_set_int(&format_opts, "reorder_queue_size", 0, 0);

		// https://ffmpeg.org/ffmpeg-protocols.html#data
		std::string url = "data:text/plain;charset=UTF-8," + sdpClause;

		int error = avformat_open_input(&ic,
			url.c_str(),
			file_iformat,
			&format_opts);

		uint8_t *readbuf = (uint8_t *)av_malloc(4096);
		AVIOContext * avio_in = avio_alloc_context(readbuf, 4096, 1, &videoQueue, &read_raw_packet, &write_packet
			, NULL);

		ic->pb = avio_in;

		ic->iformat = file_iformat;

		error = avformat_find_stream_info(ic, nullptr);

		const auto streamNumber = av_find_best_stream(ic, AVMEDIA_TYPE_VIDEO, -1, -1, nullptr, 0);

		auto codecContext = avcodec_alloc_context3(nullptr);
		if (codecContext == nullptr) {
			return 1;
		}

		if (avcodec_parameters_to_context(codecContext, ic->streams[streamNumber]->codecpar) < 0) {
			return 1;
		}

		auto decoder = avcodec_find_decoder(codecContext->codec_id);
		if (decoder == nullptr)
		{
			return 1;  // Codec not found
		}

		// Open codec
		if (avcodec_open2(codecContext, decoder, nullptr) < 0)
		{
			assert(false && "Error on codec opening");
			return 1;  // Could not open codec
		}


		AVFramePtr videoFrame(av_frame_alloc());

		AVPacket packet;

		bool stop = false;
		while (!stop)
		{
			if (av_read_frame(ic, &packet) >= 0)
			{
				if (packet.stream_index == streamNumber)
				{
					// Here it goes
					const int ret = avcodec_send_packet(codecContext, &packet);
					if (ret < 0)
					{
						av_packet_unref(&packet);
						//return 1;
						continue;
					}
					while (avcodec_receive_frame(codecContext, videoFrame.get()) == 0)
					{
						// transformation

						AVPacket avEncodedPacket;

						av_init_packet(&avEncodedPacket);
						avEncodedPacket.data = nullptr;
						avEncodedPacket.size = 0;


						cv::Mat img(videoFrame->height, videoFrame->width, CV_8UC3);

						int stride = img.step[0];

						auto img_convert_ctx = sws_getCachedContext(
							nullptr,
							codecContext->width,
							codecContext->height,
							codecContext->pix_fmt,
							codecContext->width,
							codecContext->height,
							AV_PIX_FMT_BGR24,
							SWS_POINT,//SWS_FAST_BILINEAR,
							nullptr, nullptr, nullptr);
						sws_scale(img_convert_ctx, videoFrame->data, videoFrame->linesize, 0, codecContext->height,
							&img.data,
							&stride);

						// Display the output image
						cv::imshow("Output", img);

						char ch = cv::waitKey(1);
						if (ch == 27)
						{
							stop = true;
							break;
						}
					}
				}
				av_packet_unref(&packet);
			}
		}

		avcodec_free_context(&codecContext);
		avio_context_free(&ic->pb);
		//ic->pb = nullptr;
		avformat_close_input(&ic);

	} catch (const std::exception &e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}
