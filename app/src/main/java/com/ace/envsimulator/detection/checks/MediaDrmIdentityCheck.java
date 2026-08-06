package com.ace.envsimulator.detection.checks;

import android.content.Context;
import android.media.MediaDrm;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import java.util.UUID;

public final class MediaDrmIdentityCheck extends BaseCheck {
    private static final UUID WIDEVINE = new UUID(0xedef8ba979d64aceL, 0xa3c827dcd51d21edL);
    public MediaDrmIdentityCheck() { super("mediadrm.identity", "设备身份", "MediaDrm 设备唯一标识"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        MediaDrm drm = null;
        try {
            drm = new MediaDrm(WIDEVINE);
            byte[] id = drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID);
            if (id == null || id.length == 0) return suspicious(start, "设备唯一标识为空", "Widevine deviceUniqueId length=0",
                    "MRPCS 已证实读取该字段，但风险解释尚未闭合", 85);
            return suspicious(start, "已采集设备标识摘要", "length=" + id.length + "\nsha256=" + CheckSupport.sha256(id),
                    "为保护隐私不显示原始标识；是否作为风险指纹和字段权重未知", 92);
        } catch (Exception e) {
            return suspicious(start, "MediaDrm 标识读取失败", e.getClass().getSimpleName() + ": " + e.getMessage(),
                    "读取能力已证实，失败语义和服务端阈值未知", 80);
        } finally {
            if (drm != null) drm.release();
        }
    }
}
