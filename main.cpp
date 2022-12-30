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

//#include "zm_rtp_source.h"
//#include "zm_sdp.h"


#include "zm_buffer.h"

#include "rtpdec.h"
#include "rtpdec_h264.h"

#include "fqueue.h"

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
typedef int SOCKET;
#endif

using nlohmann::json;

inline auto GetSize(const AVPacket& packet) { return packet.size; }

inline auto GetSize(const rtc::binary& packet) { return packet.size(); }


bool is_video_stream(const AVStream * stream) {
	if (stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
		return true;
	}

	//Debug(2, "Not a video type %d != %d", stream->codecpar->codec_type, AVMEDIA_TYPE_VIDEO);
	return false;
}


struct AVFrameDeleter
{
	void operator()(AVFrame *frame) const { av_frame_free(&frame); };
};

using AVFramePtr = std::unique_ptr<AVFrame, AVFrameDeleter>;

//*
struct VideoQueue
{
	FQueue<rtc::binary, 15 * 1024 * 1024, 500> mQueue;
	rtc::binary mBuffer;

	Buffer mFrame;

	bool mFrameGood = true;

	bool handlePacket(const unsigned char *packet, size_t packetLen);
};


#pragma pack(push, 1)

struct RtpDataHeader
{
	uint8_t cc : 4;     // CSRC count
	uint8_t x : 1;      // header extension flag
	uint8_t p : 1;      // padding flag
	uint8_t version : 2;  // protocol version
	uint8_t pt : 7;     // payload type
	uint8_t m : 1;      // marker bit
	uint16_t seqN;    // sequence number, network order
	uint32_t timestampN;  // timestamp, network order
	uint32_t ssrcN;     // synchronization source, network order
	uint32_t csrc[];    // optional CSRC list
};


bool VideoQueue::handlePacket(const unsigned char *packet, size_t packetLen) {
	const RtpDataHeader *rtpHeader;
	rtpHeader = (RtpDataHeader *)packet;
	int rtpHeaderSize = 12 + rtpHeader->cc * 4;
	// No need to check for nal type as non fragmented packets already have 001 start sequence appended
	bool h264FragmentEnd = //(mCodecId == AV_CODEC_ID_H264) && 
		(packet[rtpHeaderSize + 1] & 0x40);
	// M stands for Marker, it is the 8th bit
	// The interpretation of the marker is defined by a profile. It is intended
	// to allow significant events such as frame boundaries to be marked in the
	//  packet stream. A profile may define additional marker bits or specify
	//  that there is no marker bit by changing the number of bits in the payload type field.
	bool thisM = rtpHeader->m || h264FragmentEnd;

	//if (updateSeq(ntohs(rtpHeader->seqN))) {
		//Hexdump(4, packet + rtpHeaderSize, 16);

		if (mFrameGood) {
			int extraHeader = 0;

			//if (mCodecId == AV_CODEC_ID_H264) {
				int nalType = (packet[rtpHeaderSize] & 0x1f);
				//Debug(3, "Have H264 frame: nal type is %d", nalType);

				switch (nalType) {
				case 24: // STAP-A
					extraHeader = 2;
					break;
				case 25: // STAP-B
				case 26: // MTAP-16
				case 27: // MTAP-24
					extraHeader = 3;
					break;
					// FU-A and FU-B
				case 28: case 29:
					// Is this NAL the first NAL in fragmentation sequence
					if (packet[rtpHeaderSize + 1] & 0x80) {
						// Now we will form new header of frame
						mFrame.append("\x0\x0\x1\x0", 4);
						// Reconstruct NAL header from FU headers
						*(mFrame + 3) = (packet[rtpHeaderSize + 1] & 0x1f) |
							(packet[rtpHeaderSize] & 0xe0);
					}

					extraHeader = 2;
					break;
				default:
					//Debug(3, "Unhandled nalType %d", nalType);
					;
				}

				// Append NAL frame start code
				if (!mFrame.size())
					mFrame.append("\x0\x0\x1", 3);
			//} // end if H264
			mFrame.append(packet + rtpHeaderSize + extraHeader,
				packetLen - rtpHeaderSize - extraHeader);
		}
		//else {
		//	Debug(3, "NOT H264 frame: type is %d", mCodecId);
		//}

		//Hexdump(4, mFrame.head(), 16);

		if (thisM) {
			if (mFrameGood) {
				//Debug(3, "Got new frame %d, %d bytes", mFrameCount, mFrame.size());

				//{
				//  std::lock_guard<std::mutex> lck(mFrameReadyMutex);
				//  mFrameReady = true;
				//}
				//mFrameReadyCv.notify_all();

				//{
				//  std::unique_lock<std::mutex> lck(mFrameProcessedMutex);
				//  mFrameProcessedCv.wait(lck, [&]{ return mFrameProcessed || mTerminate; });
				//  mFrameProcessed = false;
				//}

				//Capture(mFrame);


				mQueue.push(rtc::binary((std::byte*)mFrame.head(), (std::byte*)mFrame.tail()));

				//size_t bytes_remaining = mFrame.size();
				//splitFrames(mFrame.head(), bytes_remaining);

				//if (mTerminate)
				//	return false;

				//mFrameCount++;
			}
			//else {
			//	Warning("Discarding incomplete frame %d, %d bytes", mFrameCount, mFrame.size());
			//}
			mFrame.clear();
		}
	//}
	//else {
	//	if (mFrame.size()) {
	//		Warning("Discarding partial frame %d, %d bytes", mFrameCount, mFrame.size());
	//	}
	//	else {
	//		Warning("Discarding frame %d", mFrameCount);
	//	}
	//	mFrameGood = false;
	//	mFrame.clear();
	//}
	if (thisM) {
		mFrameGood = true;
		//prevM = true;
	}
	//else
	//  prevM = false;

	//updateJitter(rtpHeader);

	return true;
}





typedef FQueue<AVPacket, 15 * 1024 * 1024, 500> AVQueue;


int read_packet(AVFormatContext * ctx, AVPacket *pkt)
{
	auto queue = static_cast<AVQueue*>(ctx->opaque);
	if (!queue->pop(*pkt))
		return 0;

	return pkt->size;
}



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
//*/


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

		//SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
		//sockaddr_in addr = {};
		//addr.sin_family = AF_INET;
		//addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		//addr.sin_port = htons(5000);

		//AVQueue fQueue;
		//RtpSource trans([&fQueue](AVPacket& packet) { fQueue.push(packet); }, AV_CODEC_ID_H264);

		VideoQueue videoQueue;


		// ff_rtp_parse_open


/*

		AVFormatContext *formatContext = avformat_alloc_context();

		AVInputFormat *iformat = av_find_input_format("h264");

		formatContext->iformat = iformat;

		RTPDemuxContext *s = ff_rtp_parse_open(formatContext, 96, 500);


		PayloadContext payloadContext = {};

		payloadContext.packetization_mode = 1;
		parse_profile_level_id(formatContext, &payloadContext, "42001f");

		s->parse_packet = h264_handle_packet;
		s->dynamic_protocol_context = &payloadContext;



		// preparing decoder stuff
		auto decoder = avcodec_find_decoder(AV_CODEC_ID_H264);

		auto decoderContext = avcodec_alloc_context3(decoder);
		decoderContext->pix_fmt = AV_PIX_FMT_YUV420P;
		decoderContext->codec_type = AVMEDIA_TYPE_VIDEO;

		decoderContext->time_base = { 1, AV_TIME_BASE };

		//decoderContext->flags2 |= AV_CODEC_FLAG2_CHUNKS;
		//decoderContext->ctx_flags |= AVFMTCTX_NOHEADER;

		//decoderContext->width = 1540;// 1280;
		//decoderContext->height = 960;// 720;

		AVDictionary* opts = nullptr;
		av_dict_set(&opts, "threads", "auto", 0);
		av_dict_set(&opts, "refcounted_frames", "1", 0);



		auto stream = avformat_new_stream(formatContext, decoder);
*/




		rtc::Description::Video media("video", rtc::Description::Direction::RecvOnly);
		media.addH264Codec(96);
		media.setBitrate(
		    2500); // Request 3Mbps (Browsers do not encode more than 2.5MBps from a webcam)

		auto track = pc->addTrack(media);

		auto session = std::make_shared<rtc::RtcpReceivingSession>();
		track->setMediaHandler(session);

		uint8_t *buf = nullptr;

//#define RTP_MAX_PACKET_LENGTH 8192 
//#define RECVBUF_SIZE 10 * RTP_MAX_PACKET_LENGTH      

		enum { RECVBUF_SIZE = 10 * 8192 };

		track->onMessage(
		    //[session, sock, addr](rtc::binary message) {
			   // // This is an RTP packet
			   // sendto(sock, reinterpret_cast<const char *>(message.data()), int(message.size()), 0,
			   //        reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
		    //},
			//[s, &fQueue, &buf](rtc::binary message) {
			[&videoQueue](rtc::binary message) {

				videoQueue.mQueue.push(message);


				/*
				const RtpDataHeader *rtpHeader = (RtpDataHeader *)message.data();
				int rtpHeaderSize = 12 + rtpHeader->cc * 4;

				videoQueue.mQueue.push({ message.begin() + rtpHeaderSize, message.end() - rtpHeaderSize });
				*/


				//videoQueue.handlePacket(reinterpret_cast<const unsigned char *>(message.data()), message.size());

				/*
				//trans.handlePacket(reinterpret_cast<const unsigned char *>(message.data()), message.size());
				AVPacket pkt;
				//uint8_t *buf = reinterpret_cast<uint8_t *>(message.data());

				if (!buf)
					buf = static_cast<uint8_t *>(av_malloc(RECVBUF_SIZE));

				memcpy(buf, message.data(), std::min(message.size(), (size_t)RECVBUF_SIZE));

				int ret = ff_rtp_parse_packet(s, &pkt, &buf, message.size());
				if (ret >= 0)
				{
					//pkt.pts = std::chrono::duration_cast<std::chrono::microseconds>(
					//	std::chrono::system_clock::now().time_since_epoch()).count();

					//extract_extradata(st, pkt);

					fQueue.push(pkt);
					//rtc::binary output((std::byte*)pkt.data, (std::byte*)(pkt.data + pkt.size));
					//videoQueue.mQueue.push(output);
				}
				while (ret == 1)
				{
					ret = ff_rtp_parse_packet(s, &pkt, nullptr,0);
					if (ret >= 0)
					{
						//pkt.pts = std::chrono::duration_cast<std::chrono::microseconds>(
						//	std::chrono::system_clock::now().time_since_epoch()).count();

						//extract_extradata(st, pkt);

						fQueue.push(pkt);
						//rtc::binary output((std::byte*)pkt.data, (std::byte*)(pkt.data + pkt.size));
						//videoQueue.mQueue.push(output);
					}
				}
				//*/
			},
			[](std::string message) { 
				std::cout << "*** String message: " << message << std::endl;
			});


		//av_log_set_level(AV_LOG_QUIET);

/*

		if (avcodec_open2(decoderContext, decoder, &opts) < 0)
		{
			return 1;
		}
//*/

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


		/*
				
		// experimental

		SessionDescriptor sessionDescriptor({}, sdpClause);

		auto mFormatContext = sessionDescriptor.generateFormatContext();

		// Find first video stream present
		int mVideoStreamId = -1;
		int mAudioStreamId = -1;

		AVStream* mVideoStream = nullptr;

		// Find the first video stream. 
		for (unsigned int i = 0; i < mFormatContext->nb_streams; i++) {
			if (is_video_stream(mFormatContext->streams[i])) {
				if (mVideoStreamId == -1) {
					mVideoStreamId = i;
					mVideoStream = mFormatContext->streams[i];
					mVideoStream->time_base = { 1, AV_TIME_BASE };
					continue;
				}
				else {
					Debug(2, "Have another video stream.");
				}
#if 0
			}
			else if (is_audio_stream(mFormatContext->streams[i])) {
				if (mAudioStreamId == -1) {
					mAudioStreamId = i;
					mAudioStream = mFormatContext->streams[i];
				}
				else {
					Debug(2, "Have another audio stream.");
				}
#endif
			}
			else {
				Debug(1, "Have unknown codec type in stream %d", i);
			}
		} // end foreach stream

		if (mVideoStreamId == -1) {
			Error("Unable to locate video stream");
			return -1;
		}
		if (mAudioStreamId == -1)
			Debug(3, "Unable to locate audio stream");

		// Get a pointer to the codec context for the video stream
		auto decoderContext = avcodec_alloc_context3(nullptr);
		avcodec_parameters_to_context(decoderContext, mFormatContext->streams[mVideoStreamId]->codecpar);

		// Find the decoder for the video stream
		const AVCodec *codec = avcodec_find_decoder(decoderContext->codec_id);
		if (codec == nullptr) {
			Error("Unable to locate codec %d decoder", decoderContext->codec_id);
			return -1;
		}

		// Open codec
		if (avcodec_open2(decoderContext, codec, nullptr) < 0) {
			Error("Can't open codec");
			return -1;
		}
*/





/*

		formatContext->opaque = &fQueue;
		formatContext->iformat->read_packet = read_packet;

		auto error = avformat_find_stream_info(formatContext, nullptr);


		AVFramePtr videoFrame(av_frame_alloc());

		for (;;)
		{
			AVPacket packet;
			//if (!fQueue.pop(packet))
			//{
			//	break;
			//}

			if (av_read_frame(formatContext, &packet) < 0)
				break;

			// Here it goes
			const int ret = avcodec_send_packet(decoderContext, &packet);
			if (ret < 0)
			{
				av_packet_unref(&packet);
				//emit cameraDisconnected(false);
				//return 1;
				continue;
			}
			while (//!isInterruptionRequested() && 
				avcodec_receive_frame(decoderContext, videoFrame.get()) == 0)
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
					decoderContext->width,
					decoderContext->height,
					decoderContext->pix_fmt,
					decoderContext->width,
					decoderContext->height,
					AV_PIX_FMT_BGR24,
					SWS_POINT,//SWS_FAST_BILINEAR,
					nullptr, nullptr, nullptr);
				sws_scale(img_convert_ctx, videoFrame->data, videoFrame->linesize, 0, decoderContext->height,
					&img.data,
					&stride);

				// Display the output image
				cv::imshow("Output", img);

				//{
				//	QMutexLocker locker(&m_mtxQueueSize);
				//	while (!isInterruptionRequested() && m_queueSize >= MAX_QUEUE_SIZE) {
				//		m_cvQueueSize.wait(&m_mtxQueueSize);
				//	}
				//}

				//if (!isInterruptionRequested())
				//{
				//	++m_queueSize;
				//	emit newImage(img);
				//}

				//msleep(20);
			// Break out of the loop if the user presses the Esc key
				char ch = cv::waitKey(10);
				if (ch == 27)
					break;
			}
			av_packet_unref(&packet);

		}
//*/

#if 1

//*
		std::string osFName;

		{
			std::ofstream os;
			do {
				osFName = std::tmpnam(nullptr);
			} while (os.open(osFName), !os);
			os << sdpClause;
		}

		AVInputFormat *file_iformat = av_find_input_format("sdp");
		AVFormatContext *ic = avformat_alloc_context();
		AVDictionary *format_opts = NULL;
		av_dict_set(&format_opts, "sdp_flags", "custom_io", 0);

		av_dict_set_int(&format_opts, "reorder_queue_size", 0, 0);



		int error = avformat_open_input(&ic,
			"C:/temp/video.sdp",
			//osFName.c_str(), 
			file_iformat,
			&format_opts);



		uint8_t *readbuf = (uint8_t *)av_malloc(4096);
		AVIOContext * avio_in = avio_alloc_context(readbuf, 4096, 1, &videoQueue, &read_raw_packet, &write_packet
			, NULL);

		ic->pb = avio_in;

		//ic->flags |= AVFMT_FLAG_CUSTOM_IO;
		ic->iformat = file_iformat;


//*/
	
/*
		//AVInputFormat *iformat = av_find_input_format("rtp");

		AVInputFormat formatCopy = *av_find_input_format("rtp");
		AVInputFormat *iformat = &formatCopy;
		iformat->flags &= ~AVFMT_NOFILE;
		iformat->read_header = NULL;

		AVFormatContext *ic = avformat_alloc_context();

		uint8_t *readbuf = (uint8_t *)av_malloc(4096);
		AVIOContext * avio_in = avio_alloc_context(readbuf, 4096, 0, &videoQueue, &read_raw_packet, NULL//&write_packet
			, NULL);
		ic->pb = avio_in;

		ic->flags |= AVFMT_FLAG_CUSTOM_IO;
		//ic->flags |= AVFMT_FLAG_PRIV_OPT;

		ic->iformat = iformat;




		// preparing decoder stuff
		auto decoder = avcodec_find_decoder(AV_CODEC_ID_H264);

		auto codecContext = avcodec_alloc_context3(decoder);
		codecContext->pix_fmt = AV_PIX_FMT_YUV420P;
		codecContext->codec_type = AVMEDIA_TYPE_VIDEO;

		codecContext->time_base = { 1, AV_TIME_BASE };

		//decoderContext->flags2 |= AV_CODEC_FLAG2_CHUNKS;
		//decoderContext->ctx_flags |= AVFMTCTX_NOHEADER;

		//decoderContext->width = 1540;// 1280;
		//decoderContext->height = 960;// 720;

		//AVDictionary* opts = nullptr;
		//av_dict_set(&opts, "threads", "auto", 0);
		//av_dict_set(&opts, "refcounted_frames", "1", 0);



		//decoder->init(codecContext);



		AVDictionary *streamOpts = nullptr;

		auto stream = avformat_new_stream(ic, decoder);

		stream->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
		stream->codecpar->codec_id = AV_CODEC_ID_H264;

		auto error = avformat_open_input(&ic, nullptr, iformat, &streamOpts);




//*/

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
		//if (avcodec_open2(codecContext, codec, nullptr) < 0)
		if (avcodec_open2(codecContext, decoder, nullptr) < 0)
		{
			assert(false && "Error on codec opening");
			return 1;  // Could not open codec
		}

//*

		//error = avformat_find_stream_info(ic, nullptr);

		//const auto streamNumber = av_find_best_stream(ic, AVMEDIA_TYPE_VIDEO, -1, -1, nullptr, 0);

		AVFramePtr videoFrame(av_frame_alloc());

		AVPacket packet;

		/*
		while (//!isInterruptionRequested() && 
			av_read_frame(ic, &packet) >= 0)
			*/

		for (;;)
		if (av_read_frame(ic, &packet) >= 0)
		{
			if (packet.stream_index == streamNumber)
			{
				// Here it goes
				const int ret = avcodec_send_packet(codecContext, &packet);
				if (ret < 0)
				{
					av_packet_unref(&packet);
					//emit cameraDisconnected(false);
					//return 1;
					continue;
				}
				while (//!isInterruptionRequested() && 
					avcodec_receive_frame(codecContext, videoFrame.get()) == 0)
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

					//{
					//	QMutexLocker locker(&m_mtxQueueSize);
					//	while (!isInterruptionRequested() && m_queueSize >= MAX_QUEUE_SIZE) {
					//		m_cvQueueSize.wait(&m_mtxQueueSize);
					//	}
					//}

					//if (!isInterruptionRequested())
					//{
					//	++m_queueSize;
					//	emit newImage(img);
					//}

					//msleep(20);
					char ch = cv::waitKey(10);
					if (ch == 27)
						break;
				}
			}
			av_packet_unref(&packet);
		}

//*/
#endif


		//std::cout << "Press any key to exit." << std::endl;
		//char dummy;
		//std::cin >> dummy;

	} catch (const std::exception &e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}
