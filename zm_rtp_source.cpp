//
// ZoneMinder RTP Source Class Implementation, $Date$, $Revision$
// Copyright (C) 2001-2008 Philip Coombes
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
// 

#include "zm_rtp_source.h"

//#include "zm_time.h"
//#include "zm_rtp_data.h"
//#include "zm_utils.h"
//#include <arpa/inet.h>
//#include <unistd.h>

#if defined(WIN32)
#include <windows.h>
#include <winsock2.h>
#include <winnt.h>
#include <shellapi.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET_ERROR (-1)
#endif

extern "C"
{
#include <libavcodec/avcodec.h>
}

namespace {

const char H264marker[] = {0,0,0,1};
const char H264shortmarker[] = {0,0,1};


unsigned char * findMarker(
    unsigned char *frame, size_t size, size_t &length
    ) {
  //Debug(1, "findMarker %p %d", frame, size);
  unsigned char *start = nullptr;
  for ( size_t i = 0; i < size-2; i += 1 ) {
    //Debug(1, "%d: %d %d %d", i, frame[i], frame[i+1], frame[i+2]);
    if ( (frame[i] == 0) && (frame[i+1]) == 0 && (frame[i+2] == 1) ) {
      if ( i && (frame[i-1] == 0) ) {
        start = frame + i - 1;
        length = sizeof(H264marker);
      } else {
        start = frame + i;
        length = sizeof(H264shortmarker);
      }
      break;
    }
  }
  return start;
}

enum { m_keepMarker = false };

// extract a frame
unsigned char*  extractFrame(unsigned char* frame, size_t& size, size_t& outsize) {
	unsigned char *outFrame = nullptr;
	Debug(4, "ExtractFrame: %p %zu", frame, size);
	outsize = 0;
	size_t markerLength = 0;
	unsigned char m_frameType = 0;
  unsigned char *startFrame = nullptr;
  if (size >= 3)
    startFrame = findMarker(frame, size, markerLength);
	if (startFrame != nullptr) {
    size_t endMarkerLength = 0;
		Debug(4, "startFrame: %p marker Length %zu", startFrame, markerLength);
		m_frameType = startFrame[markerLength];

		int remainingSize = size-(startFrame-frame+markerLength);
		unsigned char *endFrame = nullptr;
    if ( remainingSize > 3 ) {
      endFrame = findMarker(startFrame+markerLength, remainingSize, endMarkerLength);
    }
		Debug(4, "endFrame: %p marker Length %zu, remaining size %d", endFrame, endMarkerLength, remainingSize);

		if ( m_keepMarker ) {
			size -=  startFrame-frame;
			outFrame = startFrame;
		} else {
			size -=  startFrame-frame+markerLength;
			outFrame = &startFrame[markerLength];
		}

		if ( endFrame != nullptr ) {
			outsize = endFrame - outFrame;
		} else {
			outsize = size;
		}
		size -= outsize;
		Debug(4, "Have frame type: %d size %zu, keepmarker %d", m_frameType, outsize, m_keepMarker);
	} else if ( size >= sizeof(H264shortmarker) ) {
		Info("No marker found size %zu", size);
	}

	return outFrame;
}



}


RtpSource::RtpSource(
    //int id,
    //const std::string &localHost,
    //int localPortBase,
    //const std::string &remoteHost,
    //int remotePortBase,
    //uint32_t ssrc,
	std::function<void(AVPacket&)> callback,
	_AVCODECID codecId,
    uint16_t seq,
    uint32_t rtpClock,
    uint32_t rtpTime
     ) :
	mCallback(callback),
  //mId(id),
  //mSsrc(ssrc),
  //mLocalHost(localHost),
  //mRemoteHost(remoteHost),
  mRtpClock(rtpClock),
  mCodecId(codecId),
  mFrame(65536),
  mFrameCount(0),
  mFrameGood(true),
  //prevM(false),
  //mFrameReady(false),
  //mFrameProcessed(false),
  mTerminate(false)
{
  //char hostname[256] = "";
  //gethostname(hostname, sizeof(hostname));

  //mCname = stringtf("zm-%d@%s", mId, hostname);
  //Debug(3, "RTP CName = %s", mCname.c_str());

  init(seq);
  mMaxSeq = seq - 1;
  mProbation = MIN_SEQUENTIAL;

  //mLocalPortChans[0] = localPortBase;
  //mLocalPortChans[1] = localPortBase+1;

  //mRemotePortChans[0] = remotePortBase;
  //mRemotePortChans[1] = remotePortBase+1;

  mRtpFactor = mRtpClock;

  mBaseTimeReal = std::chrono::system_clock::now();
  mBaseTimeNtp = {};
  mBaseTimeRtp = rtpTime;

  //mLastSrTimeReal = {};
  mLastSrTimeNtp = {};
  mLastSrTimeRtp = 0;

  mLastSrTimeNtpSecs = 0;
  mLastSrTimeNtpFrac = 0;
  mExpectedPackets = 0;
  mLostPackets = 0;
  mLostFraction = 0;

  if ( mCodecId != AV_CODEC_ID_H264 && mCodecId != AV_CODEC_ID_MPEG4 )
    Warning("The device is using a codec (%d) that may not be supported. Do not be surprised if things don't work.", mCodecId);
}

RtpSource::~RtpSource() {
  mTerminate = true;
  //mFrameReadyCv.notify_all();
  //mFrameProcessedCv.notify_all();
}

void RtpSource::init(uint16_t seq) {
  Debug(3, "Initialising sequence");
  mBaseSeq = seq;
  mMaxSeq = seq;
  mBadSeq = RTP_SEQ_MOD + 1;  // so seq == mBadSeq is false
  mCycles = 0;
  mReceivedPackets = 0;
  mReceivedPrior = 0;
  mExpectedPrior = 0;
  // other initialization
  mJitter = 0;
  mTransit = 0;
}

bool RtpSource::updateSeq(uint16_t seq) {
  uint16_t uDelta = seq - mMaxSeq;

  // Source is not valid until MIN_SEQUENTIAL packets with
  // sequential sequence numbers have been received.
  Debug(5, "Seq: %d", seq);

  if ( mProbation) {
    // packet is in sequence
    if ( seq == mMaxSeq + 1 ) {
      Debug(3, "Sequence in probation %d, in sequence", mProbation);
      mProbation--;
      mMaxSeq = seq;
      if ( mProbation == 0 ) {
        init(seq);
        mReceivedPackets++;
        return true;
      }
    } else {
      Warning("Sequence in probation %d, out of sequence", mProbation);
      mProbation = MIN_SEQUENTIAL - 1;
      mMaxSeq = seq;
      return false;
    }
    return true;
  } else if ( uDelta < MAX_DROPOUT ) {
    if ( uDelta == 1 ) {
      Debug(4, "Packet in sequence, gap %d", uDelta);
    } else {
      Warning("Packet in sequence, gap %d", uDelta);
    }

    // in order, with permissible gap
    if ( seq < mMaxSeq ) {
      // Sequence number wrapped - count another 64K cycle.
      mCycles += RTP_SEQ_MOD;
    }
    mMaxSeq = seq;
  } else if ( uDelta <= RTP_SEQ_MOD - MAX_MISORDER ) {
    Warning("Packet out of sequence, gap %d", uDelta);
    // the sequence number made a very large jump
    if ( seq == mBadSeq ) {
      Debug(3, "Restarting sequence");
      // Two sequential packets -- assume that the other side
      // restarted without telling us so just re-sync
      // (i.e., pretend this was the first packet).
      init(seq);
    } else {
      mBadSeq = (seq + 1) & (RTP_SEQ_MOD-1);
      return false;
    }
  } else {
    Warning("Packet duplicate or reordered, gap %d", uDelta);
    // duplicate or reordered packet
    return false;
  }
  mReceivedPackets++;
  return( uDelta==1?true:false );
}

void RtpSource::updateJitter( const RtpDataHeader *header ) {
  if (mRtpFactor > 0) {
    auto now = std::chrono::system_clock::now();
    auto time_diff = std::chrono::duration_cast<std::chrono::duration<double>>(now - mBaseTimeReal);

    uint32_t localTimeRtp = mBaseTimeRtp + static_cast<uint32_t>(time_diff.count() * mRtpFactor);
    uint32_t packetTransit = localTimeRtp - ntohl(header->timestampN);

    Debug(5,
          "Delta rtp = %.6f\n Local RTP time = %x Packet RTP time = %x Packet transit RTP time = %x",
          time_diff.count(),
          localTimeRtp,
          ntohl(header->timestampN),
          packetTransit);

    if ( mTransit > 0 ) {
      // Jitter
      int d = packetTransit - mTransit;
      Debug(5, "Jitter D = %d", d);
      if ( d < 0 )
        d = -d;
      //mJitter += (1./16.) * ((double)d - mJitter);
      mJitter += d - ((mJitter + 8) >> 4);
    }
    mTransit = packetTransit;
  } else {
    mJitter = 0;
  }
  Debug(5, "RTP Jitter: %d", mJitter);
}

void RtpSource::updateRtcpData(
    uint32_t ntpTimeSecs,
    uint32_t ntpTimeFrac,
    uint32_t rtpTime) {
  //timeval ntpTime = zm::chrono::duration_cast<timeval>(
  //    Seconds(ntpTimeSecs) + Microseconds((Microseconds::period::den * (ntpTimeFrac >> 16)) / (1 << 16)));

	using namespace std::chrono_literals;

	auto ntpTime = std::chrono::seconds(ntpTimeSecs) 
		+ std::chrono::microseconds((std::chrono::microseconds::period::den * (ntpTimeFrac >> 16)) / (1 << 16));

  Debug(5, "ntpTime: %ld.%06ld, rtpTime: %x", ntpTime.count() / 1000000, ntpTime.count() % 1000000, rtpTime);

  if ( mBaseTimeNtp == 0s ) {
    mBaseTimeReal = std::chrono::system_clock::now();
    mBaseTimeNtp = ntpTime;
    mBaseTimeRtp = rtpTime;
  } else if ( !mRtpClock ) {
    Debug(5, "lastSrNtpTime: %ld.%06ld, rtpTime: %x"
        "ntpTime: %ld.%06ld, rtpTime: %x",
        mLastSrTimeNtp.count() / 1000000, mLastSrTimeNtp.count() % 1000000, rtpTime,
        ntpTime.count() / 1000000, ntpTime.count() % 1000000, rtpTime);

    //FPSeconds diffNtpTime =
    //    zm::chrono::duration_cast<Microseconds>(ntpTime) - zm::chrono::duration_cast<Microseconds>(mBaseTimeNtp);

	auto diffNtpTime = ntpTime - mBaseTimeNtp;

    uint32_t diffRtpTime = rtpTime - mBaseTimeRtp;
    mRtpFactor = static_cast<uint32_t>(diffRtpTime / diffNtpTime.count());

    Debug( 5, "NTP-diff: %.6f RTP-diff: %d RTPfactor: %d",
        diffNtpTime.count(), diffRtpTime, mRtpFactor);
  }
  mLastSrTimeNtpSecs = ntpTimeSecs;
  mLastSrTimeNtpFrac = ntpTimeFrac;
  mLastSrTimeNtp = ntpTime;
  mLastSrTimeRtp = rtpTime;
}

void RtpSource::updateRtcpStats() {
  uint32_t extendedMax = mCycles + mMaxSeq;
  mExpectedPackets = extendedMax - mBaseSeq + 1;
  // The number of packets lost is defined to be the number of packets
  // expected less the number of packets actually received:
  mLostPackets = mExpectedPackets - mReceivedPackets;
  uint32_t expectedInterval = mExpectedPackets - mExpectedPrior;
  mExpectedPrior = mExpectedPackets;
  uint32_t receivedInterval = mReceivedPackets - mReceivedPrior;
  mReceivedPrior = mReceivedPackets;
  int32_t lostInterval = expectedInterval - receivedInterval;

  if ( expectedInterval == 0 || lostInterval <= 0 )
    mLostFraction = 0;
  else
    mLostFraction = (lostInterval << 8) / expectedInterval;

  Debug(5,
        "Expected packets = %d\n Lost packets = %d\n Expected interval = %d\n Received interval = %d\n Lost interval = %d\n Lost fraction = %d\n",
        mExpectedPackets,
        mLostPackets,
        expectedInterval,
        receivedInterval,
        lostInterval,
        mLostFraction);
}

bool RtpSource::handlePacket(const unsigned char *packet, size_t packetLen) {
  const RtpDataHeader *rtpHeader;
  rtpHeader = (RtpDataHeader *)packet;
  int rtpHeaderSize = 12 + rtpHeader->cc * 4;
  // No need to check for nal type as non fragmented packets already have 001 start sequence appended
  bool h264FragmentEnd = (mCodecId == AV_CODEC_ID_H264) && (packet[rtpHeaderSize+1] & 0x40);
  // M stands for Marker, it is the 8th bit
  // The interpretation of the marker is defined by a profile. It is intended
  // to allow significant events such as frame boundaries to be marked in the
  //  packet stream. A profile may define additional marker bits or specify
  //  that there is no marker bit by changing the number of bits in the payload type field.
  bool thisM = rtpHeader->m || h264FragmentEnd;

  if ( updateSeq(ntohs(rtpHeader->seqN)) ) {
    Hexdump(4, packet+rtpHeaderSize, 16);

    if ( mFrameGood ) {
      int extraHeader = 0;

      if ( mCodecId == AV_CODEC_ID_H264 ) {
        int nalType = (packet[rtpHeaderSize] & 0x1f);
        Debug(3, "Have H264 frame: nal type is %d", nalType);

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
              if ( packet[rtpHeaderSize+1] & 0x80 ) {
                // Now we will form new header of frame
                mFrame.append( "\x0\x0\x1\x0", 4 );
                // Reconstruct NAL header from FU headers
                *(mFrame+3) = (packet[rtpHeaderSize+1] & 0x1f) |
                  (packet[rtpHeaderSize] & 0xe0);
              }

              extraHeader = 2;
              break;
          default:
              Debug(3, "Unhandled nalType %d", nalType);
        }

        // Append NAL frame start code
        if ( !mFrame.size() )
          mFrame.append("\x0\x0\x1", 3);
      } // end if H264
      mFrame.append(packet+rtpHeaderSize+extraHeader,
          packetLen-rtpHeaderSize-extraHeader);
    } else {
      Debug(3, "NOT H264 frame: type is %d", mCodecId);
    }

    Hexdump(4, mFrame.head(), 16);

    if ( thisM ) {
      if ( mFrameGood ) {
        Debug(3, "Got new frame %d, %d bytes", mFrameCount, mFrame.size());

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

		Capture(mFrame);

		//size_t bytes_remaining = mFrame.size();
		//splitFrames(mFrame.head(), bytes_remaining);

        if (mTerminate)
          return false;

        mFrameCount++;
      } else {
        Warning("Discarding incomplete frame %d, %d bytes", mFrameCount, mFrame.size());
      }
      mFrame.clear();
    }
  } else {
    if ( mFrame.size() ) {
      Warning("Discarding partial frame %d, %d bytes", mFrameCount, mFrame.size());
    } else {
      Warning("Discarding frame %d", mFrameCount);
    }
    mFrameGood = false;
    mFrame.clear();
  }
  if ( thisM ) {
    mFrameGood = true;
    //prevM = true;
  } 
  //else
  //  prevM = false;

  updateJitter(rtpHeader);

  return true;
}

//bool RtpSource::getFrame(Buffer &buffer) {
//  {
//    std::unique_lock<std::mutex> lck(mFrameReadyMutex);
//    mFrameReadyCv.wait(lck, [&]{ return mFrameReady || mTerminate; });
//    mFrameReady = false;
//  }
//
//  if (mTerminate)
//    return false;
//
//  buffer = mFrame;
//  {
//    std::lock_guard<std::mutex> lck(mFrameProcessedMutex);
//    mFrameProcessed = true;
//  }
//  mFrameProcessedCv.notify_all();
//  Debug(4, "Copied %d bytes", buffer.size());
//  return true;
//}



void RtpSource::splitFrames(unsigned char* frame, size_t &frameSize) {
	//std::list< std::pair<unsigned char*, size_t> > frameList;

	size_t bufSize = frameSize;
	size_t size = 0;
	unsigned char* buffer = extractFrame(frame, bufSize, size);
	while (buffer != nullptr) {

		//frameList.push_back(std::pair<unsigned char*, size_t>(buffer, size));

		Capture(Buffer(buffer - 4, size + 4));

		if (!bufSize)
			break;

		buffer = extractFrame(&buffer[size], bufSize, size);
	}  // end while buffer
	frameSize = bufSize;
	//return frameList;
}



void RtpSource::Capture(Buffer &buffer)//std::shared_ptr<ZMPacket> &zm_packet) 
{
	//int frameComplete = false;
	//AVPacket *packet;// TODO = zm_packet->packet.get();

	//while (!frameComplete) {
	//	buffer.clear();
	//	if (!rtspThread || rtspThread->IsStopped() || zm_terminate)
	//		return -1;

	//	if (rtspThread->getFrame(buffer)) {

	bool keyframe = false;

			Debug(3, "Read frame %d bytes", buffer.size());
			Hexdump(4, buffer.head(), 16);

			if (!buffer.size())
				return;// -1;

			if (/*mVideoCodecContext->codec_id*/mCodecId == AV_CODEC_ID_H264) {
				// SPS and PPS frames should be saved and appended to IDR frames
				int nalType = (buffer.head()[3] & 0x1f);

				// SPS The SPS NAL unit contains parameters that apply to a series of consecutive coded video pictures
				if (nalType == 1) {
				}
				else if (nalType == 7) {
					lastSps = buffer;
					return; // continue;
				}
				else if (nalType == 8) {
					// PPS The PPS NAL unit contains parameters that apply to the decoding of one or more individual pictures inside a coded video sequence
					lastPps = buffer;
					return; // continue;
				}
				else if (nalType == 5) {
					//packet->flags |= AV_PKT_FLAG_KEY;
					keyframe = true;
					//zm_packet->keyframe = 1;
					// IDR
					buffer += lastSps;
					buffer += lastPps;
				}
				else {
					Debug(2, "Unknown nalType %d", nalType);
				}
			}
			else {
				Debug(3, "Not an h264 packet");
			}

			//while ( (!frameComplete) && (buffer.size() > 0) ) {
			if (buffer.size() > 0) {

				AVPacket packet;
				//av_init_packet(&packet);
				av_new_packet(&packet, buffer.size());

				//packet->data = (uint8_t*)av_malloc(buffer.size());

				memcpy(packet.data, buffer.head(), buffer.size());

				//packet->data = buffer.head();
				//packet->size = buffer.size();
				//bytes += packet->size;
				buffer -= packet.size;

				if (keyframe)
					packet.flags |= AV_PKT_FLAG_KEY;

				//struct timeval now;
				//gettimeofday(&now, nullptr);
				//packet->pts = packet->dts = now.tv_sec * 1000000 + now.tv_usec;

				packet.pts = std::chrono::duration_cast<std::chrono::microseconds>(
					std::chrono::system_clock::now().time_since_epoch()).count();


				//zm_packet->codec_type = mVideoCodecContext->codec_type;
				//zm_packet->stream = mVideoStream;
				//frameComplete = true;

				mCallback(packet);

				Debug(2, "Frame: %d - %d/%d", mFrameCount, packet.size, buffer.size());
			}
	//	} /* getFrame() */
	//} // end while true

	//return 1;
} // end int RemoteCameraRtsp::Capture(ZMPacket &packet)
