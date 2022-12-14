cmake_minimum_required(VERSION 3.7)

find_path(AVCODEC_INCLUDE_DIR libavcodec/avcodec.h)
find_library(AVCODEC_LIBRARY avcodec)

find_path(AVFORMAT_INCLUDE_DIR libavformat/avformat.h)
find_library(AVFORMAT_LIBRARY avformat)

find_path(AVUTIL_INCLUDE_DIR libavutil/avutil.h)
find_library(AVUTIL_LIBRARY avutil)

find_path(AVDEVICE_INCLUDE_DIR libavdevice/avdevice.h)
find_library(AVDEVICE_LIBRARY avdevice)

find_path(SWSCALE_INCLUDE_DIR libswscale/swscale.h)
find_library(SWSCALE_LIBRARY swscale)

find_path(SWRESAMPLE_INCLUDE_DIR libswresample/swresample.h)
find_library(SWRESAMPLE_LIBRARY swresample)


# Requires OpenCV
FIND_PACKAGE( OpenCV 4 REQUIRED )


set(MEDIA_UWP_RESOURCES
	uwp/Logo.png
	uwp/package.appxManifest
	uwp/SmallLogo.png
	uwp/SmallLogo44x44.png
	uwp/SplashScreen.png
	uwp/StoreLogo.png
	uwp/Windows_TemporaryKey.pfx
)

if(CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
	add_executable(datachannel-media-receiver-v2 main.cpp zm_sdp.cpp zm_rtp_source.cpp rtpdec.cpp rtpdec_h264.cpp ${MEDIA_UWP_RESOURCES})
else()
	add_executable(datachannel-media-receiver-v2 main.cpp zm_sdp.cpp zm_rtp_source.cpp rtpdec.cpp rtpdec_h264.cpp)
endif()

set_target_properties(datachannel-media-receiver-v2 PROPERTIES
    CXX_STANDARD 17
    OUTPUT_NAME media-receiver-v2)

set_target_properties(datachannel-media-receiver-v2 PROPERTIES
	XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER com.github.paullouisageneau.libdatachannel.examples.media-receiver-v2)

find_package(Threads REQUIRED)
target_link_libraries(datachannel-media-receiver-v2 LibDataChannel::LibDataChannel Threads::Threads nlohmann_json
    ${FFMPEG_LIBRARIES} 
    ${AVCODEC_LIBRARY} 
    ${AVFORMAT_LIBRARY} 
    ${AVUTIL_LIBRARY} 
    ${AVDEVICE_LIBRARY}
    ${SWSCALE_LIBRARY}
    ${SWRESAMPLE_LIBRARY}
    ${OpenCV_LIBRARIES}
)

if(MSVC)
	add_custom_command(TARGET datachannel-media-receiver-v2 POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
		"$<TARGET_FILE_DIR:datachannel>/datachannel.dll"
		$<TARGET_FILE_DIR:datachannel-media-receiver-v2>
	)
endif()
