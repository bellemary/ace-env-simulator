package com.ace.envsimulator.detection;

import android.content.Context;
import com.ace.envsimulator.model.DetectionResult;
import java.util.ArrayList;
import java.util.List;

public final class SequentialDetectionRunner {
    public interface Listener {
        void onProgress(int completed, int total, DetectionResult result);
    }

    public List<DetectionResult> run(Context context, List<DetectionCheck> checks, Listener listener) {
        List<DetectionResult> results = new ArrayList<>();
        for (int i = 0; i < checks.size(); i++) {
            if (Thread.currentThread().isInterrupted()) break;
            DetectionCheck check = checks.get(i);
            DetectionResult result;
            long start = System.nanoTime();
            try {
                result = check.run(context);
            } catch (Throwable error) {
                long elapsed = (System.nanoTime() - start) / 1_000_000L;
                result = DetectionResult.suspicious(check.id(), "执行状态", check.title(),
                        "该项执行失败，按未决风险处理", error.getClass().getSimpleName() + ": " + error.getMessage(),
                        "单项异常不应中断后续检测", 30, elapsed);
            }
            result = BasicEvidenceCatalog.enrich(result);
            results.add(result);
            if (listener != null) listener.onProgress(i + 1, checks.size(), result);
        }
        return results;
    }
}
