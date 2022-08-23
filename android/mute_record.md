# Android 静音录制视频上传到服务器​
最近项目有个需求是：静音录制视频，上传到服务器，在网上搜了很多方法，也没有很好的解决。最后想了一种代替方法，录制的时候还是有声录制，在录制完后，只提取视频中的视频流，不要音频，再将提取出来的数据做成一个MP4文件上传。下面是源码：
```java
import android.media.MediaCodec;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.media.MediaMuxer;

import java.io.File;
import java.nio.ByteBuffer;

/**
 * Created by gouhao on 12/8/2016.
 */
public class VideoUtils {

    public static void extractVideoFromMediaFile(String filePath) {
        //存放提取视频的临时文件
        String tPath = filePath.replace(".mp4", "tmp.mp4");
        MediaExtractor mediaExtractor = new MediaExtractor();
        MediaMuxer mediaMuxer = null;
        try {
            mediaExtractor.setDataSource(filePath);
            int tVideoIndex = findVideoTrackIndex(mediaExtractor);
            if(tVideoIndex == -1) {
               return;
            }
            MediaFormat trackFormat = mediaExtractor.getTrackFormat(tVideoIndex);
            mediaExtractor.selectTrack(tVideoIndex);
            int frameRate;
            //获取帧率，有的视频的信息中没有帧率这个KEY
            if(trackFormat.containsKey(MediaFormat.KEY_FRAME_RATE)) {
                frameRate = trackFormat.getInteger(MediaFormat.KEY_FRAME_RATE);
            } else {
                frameRate = 20;
            }
            mediaMuxer = new MediaMuxer(tPath, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4);
            mediaMuxer.setOrientationHint(trackFormat.getInteger(MediaFormat.KEY_ROTATION));
            int videoTrackIndex = mediaMuxer.addTrack(trackFormat);
            mediaMuxer.start();
            muxVideo(mediaExtractor, mediaMuxer, videoTrackIndex, frameRate);
            deleteSourceRenameNew(filePath, tPath);
        }catch (Exception e) {
            e.printStackTrace();
        } finally {
            mediaExtractor.release();
            mediaMuxer.stop();
            mediaMuxer.release();
        }
    }

    private static int findVideoTrackIndex(MediaExtractor mediaExtractor) {
        int trackCount = mediaExtractor.getTrackCount();
        for (int i = 0; i < trackCount; i++) {
            MediaFormat trackFormat = mediaExtractor.getTrackFormat(i);
            String mineType = trackFormat.getString(MediaFormat.KEY_MIME);
            if (mineType.startsWith("video/")) {
                return i;
            }
        }
        return -1;
    }

    protected static void muxVideo(MediaExtractor mediaExtractor, MediaMuxer mediaMuxer, int videoTrackIndex, int frameRate) {
        if (mediaMuxer == null) return;
        MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
        info.presentationTimeUs = 0;
        ByteBuffer byteBuffer = ByteBuffer.allocate(500 * 1024);
        int readSampleCount = 0;
        while (true) {
            readSampleCount = mediaExtractor.readSampleData(byteBuffer, 0);
            if (readSampleCount < 0) {
                break;
            }
            info.offset = 0;
            info.size = readSampleCount;
            info.flags = MediaCodec.BUFFER_FLAG_KEY_FRAME;
            info.presentationTimeUs += 1000 * 1000 / frameRate;
            mediaMuxer.writeSampleData(videoTrackIndex, byteBuffer, info);
            mediaExtractor.advance();
        }
    }

    protected static void deleteSourceRenameNew(String filePath, String tPath) {
        File videoFile = new File(tPath);
        if (videoFile != null) {
            new File(filePath).delete();
            File f = new File(filePath);
            videoFile.renameTo(f);
        }
    }
}
```
主要用了MediaExtractor和MediaMuxer这两个Andoird自带的提取器和合成器。

​