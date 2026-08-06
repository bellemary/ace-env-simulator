package com.ace.envsimulator.detection;

import android.content.Context;
import com.ace.envsimulator.model.DetectionResult;

public interface DetectionCheck {
    String id();
    String title();
    DetectionResult run(Context context) throws Exception;
}
