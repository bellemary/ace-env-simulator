package com.ace.envsimulator;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.net.Uri;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.OnBackPressedCallback;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import com.ace.envsimulator.advanced.AdvancedScanner;
import com.ace.envsimulator.advanced.AdvancedSessionService;
import com.ace.envsimulator.advanced.ResultExporter;
import com.ace.envsimulator.advanced.RootShell;
import com.ace.envsimulator.databinding.ActivityMainBinding;
import com.ace.envsimulator.detection.BasicDetectionCatalog;
import com.ace.envsimulator.detection.BasicResultInterpreter;
import com.ace.envsimulator.detection.SequentialDetectionRunner;
import com.ace.envsimulator.model.DetectionResult;
import com.ace.envsimulator.model.DetectionStatus;
import com.ace.envsimulator.report.ReportRepository;
import com.ace.envsimulator.ui.DetectionResultAdapter;
import com.ace.envsimulator.ui.DetectionResultAdapter.ListItem;
import com.ace.envsimulator.ui.DetectionResultAdapter.ResultItem;
import com.ace.envsimulator.ui.DetectionResultAdapter.SectionItem;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final List<DetectionResult> allResults = new ArrayList<>();
    private DetectionResultAdapter adapter;
    private ReportRepository.Mode mode;
    private File reportFile;
    private File decodedDirectory;
    private boolean scanRunning;
    private Future<?> activeTask;
    private int scanGeneration;
    private boolean advancedPreparing;
    private final Handler liveHandler = new Handler(Looper.getMainLooper());
    private final Runnable livePollTask = new Runnable() {
        @Override public void run() {
            refreshLiveCounters();
            if (AdvancedSessionService.isActive(MainActivity.this)) {
                liveHandler.postDelayed(this, 1500L);
            }
        }
    };

    @Override protected void onCreate(@Nullable Bundle state) {
        super.onCreate(state);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        adapter = new DetectionResultAdapter(this::showDetail);
        binding.resultList.setLayoutManager(new LinearLayoutManager(this));
        binding.resultList.setAdapter(adapter);
        binding.basicCard.setOnClickListener(v -> startBasic());
        binding.advancedCard.setOnClickListener(v -> startAdvanced());
        binding.resumeTargetButton.setOnClickListener(v -> launchTargetApp());
        binding.finishAdvancedSessionButton.setOnClickListener(v -> finishAdvancedSession());
        binding.backButton.setOnClickListener(v -> showHome());
        binding.filterAll.setOnClickListener(v -> applyFilter(0));
        binding.filterRisk.setOnClickListener(v -> applyFilter(1));
        binding.filterPass.setOnClickListener(v -> applyFilter(2));
        binding.exportButton.setOnClickListener(v -> exportReport());
        binding.aboutVersionLabel.setOnClickListener(v -> showAbout());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() {
                if (binding.resultsPanel.getVisibility() == View.VISIBLE) showHome(); else finish();
            }
        });
        binding.homePanel.setAlpha(0f);
        binding.homePanel.setTranslationY(24f);
        AnimatorSet entrance = new AnimatorSet();
        entrance.playTogether(ObjectAnimator.ofFloat(binding.homePanel, View.ALPHA, 0f, 1f),
                ObjectAnimator.ofFloat(binding.homePanel, View.TRANSLATION_Y, 24f, 0f));
        entrance.setDuration(260); entrance.start();
        refreshAdvancedSessionControls();
        if (AdvancedSessionService.isActive(this)) {
            Toast.makeText(this, "扫描进行中，返回游戏继续采集或点击结束扫描生成报告", Toast.LENGTH_LONG).show();
            liveHandler.post(livePollTask);
        }
    }

    private void startBasic() {
        if (scanRunning) return;
        mode = ReportRepository.Mode.BASIC;
        final int generation = openResults("基础检测模式", "正在准备逐项检测");
        List<com.ace.envsimulator.detection.DetectionCheck> checks = BasicDetectionCatalog.create();
        binding.progress.setMax(checks.size()); binding.progress.setProgress(0);
        activeTask = worker.submit(() -> {
            List<DetectionResult> results = new SequentialDetectionRunner().run(getApplicationContext(), checks,
                    (completed, total, result) -> runOnUiThread(() -> { if (generation == scanGeneration) addProgress(result, "正在执行 " + completed + " / " + total, completed, total); }));
            List<DetectionResult> interpreted = BasicResultInterpreter.appendSummaries(results);
            runOnUiThread(() -> { if (generation == scanGeneration) finishScan(interpreted); });
        });
    }

    private void startAdvanced() {
        if (scanRunning || advancedPreparing) return;
        if (AdvancedSessionService.isActive(this)) {
            launchTargetApp();
            return;
        }
        advancedPreparing = true;
        Toast.makeText(this, "正在验证 Root 并启动游戏", Toast.LENGTH_SHORT).show();
        worker.submit(() -> {
            RootShell.Result root = new RootShell().request();
            runOnUiThread(() -> {
                advancedPreparing = false;
                if (root.exitCode != 0) {
                    Toast.makeText(this, "Root 授权未完成，高级模式未启动", Toast.LENGTH_LONG).show();
                    return;
                }
                Intent launch = getPackageManager().getLaunchIntentForPackage("com.tencent.tmgp.dfm");
                if (launch == null) {
                    Toast.makeText(this, "未找到目标应用启动入口", Toast.LENGTH_LONG).show();
                    return;
                }
                // 启动高级采集服务（自动启动游戏 + 持续扫描内存）
                Intent service = new Intent(this, AdvancedSessionService.class).setAction(AdvancedSessionService.ACTION_START);
                if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service);
                refreshAdvancedSessionControls();
                liveHandler.post(livePollTask);
            });
        });
    }

    private void launchTargetApp() {
        Intent launch = getPackageManager().getLaunchIntentForPackage("com.tencent.tmgp.dfm");
        if (launch == null) {
            Toast.makeText(this, "未找到目标应用启动入口", Toast.LENGTH_LONG).show();
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        startActivity(launch);
    }

    private void finishAdvancedSession() {
        if (scanRunning || !AdvancedSessionService.hasSession(this)) return;
        binding.finishAdvancedSessionButton.setEnabled(false);
        binding.advancedSessionStatus.setText("正在结束扫描并整理 ano_tmp 文件…");
        liveHandler.removeCallbacks(livePollTask);
        startService(new Intent(this, AdvancedSessionService.class).setAction(AdvancedSessionService.ACTION_STOP));
        binding.getRoot().postDelayed(() -> {
            refreshAdvancedSessionControls();
            startAdvancedAnalysis();
        }, 2_800L);
    }

    private void startAdvancedAnalysis() {
        if (scanRunning) return;
        mode = ReportRepository.Mode.ADVANCED;
        final int generation = openResults("高级模式", "正在整理内存扫描与文件解密结果");
        binding.progress.setMax(1); binding.progress.setProgress(0);
        activeTask = worker.submit(() -> {
            AdvancedScanner.ScanOutput output = new AdvancedScanner().run(getApplicationContext(), (stage, completed, total, result) ->
                    runOnUiThread(() -> {
                        if (generation != scanGeneration) return;
                        if (result != null) addProgress(result, stage, completed, Math.max(1, total));
                        else binding.stageText.setText(stage);
                    }));
            runOnUiThread(() -> { if (generation == scanGeneration) { decodedDirectory = output.artifactDirectory; finishScan(output.results); } });
        });
    }

    @Override protected void onResume() {
        super.onResume();
        refreshAdvancedSessionControls();
        if (AdvancedSessionService.isActive(this)) {
            liveHandler.removeCallbacks(livePollTask);
            liveHandler.post(livePollTask);
        }
    }

    @Override protected void onPause() {
        super.onPause();
        liveHandler.removeCallbacks(livePollTask);
    }

    private void refreshAdvancedSessionControls() {
        if (binding == null) return;
        boolean active = AdvancedSessionService.isActive(this);
        binding.advancedSessionPanel.setVisibility(active ? View.VISIBLE : View.GONE);
        binding.finishAdvancedSessionButton.setEnabled(active);
        if (active) {
            binding.advancedSessionStatus.setText("扫描持续运行中。返回游戏进入大厅或对局，结束后回到本界面生成报告。");
            binding.liveRoundLabel.setText("● LIVE");
        }
    }

    private void refreshLiveCounters() {
        if (binding == null) return;
        String reportPath = AdvancedSessionService.getReportPath(this);
        int memHits = 0;
        int fileCount = 0;
        if (!reportPath.isEmpty()) {
            File reportFile = new File(reportPath);
            if (reportFile.exists()) {
                try {
                    byte[] data = new byte[(int) Math.min(reportFile.length(), 64L * 1024L)];
                    java.io.FileInputStream in = new java.io.FileInputStream(reportFile);
                    int read = in.read(data); in.close();
                    if (read > 0) {
                        String text = new String(data, 0, read, java.nio.charset.StandardCharsets.UTF_8);
                        for (String line : text.split("\\r?\\n")) {
                            if (line.contains("[内存命中 #")) memHits++;
                            if (line.contains("[文件解密 #")) fileCount++;
                        }
                    }
                } catch (Exception ignored) {}
            }
        }
        binding.liveMemoryCounter.setText(String.format(Locale.US,
                "内存命中 %d 项 · 文件解密 %d 项", memHits, fileCount));
    }

    private int openResults(String title, String stage) {
        int generation = ++scanGeneration;
        scanRunning = true; reportFile = null; decodedDirectory = null; allResults.clear();
        adapter.submitItems(new ArrayList<>());
        boolean advanced = mode == ReportRepository.Mode.ADVANCED;
        adapter.setAdvanced(advanced);
        binding.advancedPipeline.setVisibility(advanced ? View.VISIBLE : View.GONE);
        binding.summaryBar.setBackgroundResource(advanced ? R.drawable.bg_card_primary : R.drawable.bg_card);
        binding.progress.setIndicatorColor(getColor(advanced ? R.color.primary : R.color.primary));
        binding.filterAll.setText("全部");
        binding.filterRisk.setText(advanced ? "异常" : "风险");
        binding.filterPass.setText(advanced ? "正常" : "通过");
        binding.modeTitle.setText(title); binding.stageText.setText(stage);
        binding.summaryTitle.setText(advanced ? "正在生成报告" : "检测进行中");
        binding.summaryDetail.setText(advanced ? "先呈现内存扫描结果，再呈现文件解密结果" : "所有项目都会执行，不因前项命中而停止");
        binding.verdictIndicator.setBackgroundResource(R.drawable.bg_dot_neutral);
        binding.exportButton.setEnabled(false);
        binding.homePanel.setVisibility(View.GONE); binding.resultsPanel.setVisibility(View.VISIBLE);
        binding.resultsPanel.setAlpha(0f); binding.resultsPanel.animate().alpha(1f).setDuration(200).start();
        return generation;
    }

    private void addProgress(DetectionResult result, String stage, int completed, int total) {
        if (isFilteredOut(result)) return;
        boolean exists = false;
        for (DetectionResult current : allResults) if (current.id.equals(result.id)) { exists = true; break; }
        if (!exists) allResults.add(result);
        adapter.submitItems(buildListItems(allResults, mode));
        binding.stageText.setText(stage);
        binding.progress.setMax(Math.max(1, total)); binding.progress.setProgress(Math.min(completed, Math.max(1, total)), true);
        binding.resultCountLabel.setText(allResults.size() + " 项");
        binding.resultList.scrollToPosition(Math.max(0, adapter.getItemCount() - 1));
        updateSummary(false);
    }

    private void finishScan(List<DetectionResult> results) {
        allResults.clear();
        for (DetectionResult r : results) if (!isFilteredOut(r)) allResults.add(r);
        adapter.submitItems(buildListItems(allResults, mode));
        scanRunning = false;
        binding.stageText.setText(mode == ReportRepository.Mode.ADVANCED
                ? "扫描完成 · 点击任一项查看原始内容与解释" : "检测完成 · 点击任一结果查看证据");
        binding.progress.setMax(1); binding.progress.setProgress(1, true); binding.exportButton.setEnabled(true);
        binding.resultCountLabel.setText(allResults.size() + " 项");
        updateSummary(true);
        if (mode == ReportRepository.Mode.ADVANCED) saveAdvancedReportAsync();
    }

    /** v2.6: 高级模式完成后自动保存结果到 /storage/emulated/0/ACE解密结果/ */
    private void saveAdvancedReportAsync() {
        if (!ResultExporter.hasStoragePermission()) {
            new AlertDialog.Builder(this)
                    .setTitle("保存扫描结果")
                    .setMessage("需要「所有文件访问」权限才能将结果保存到本地存储。\n\n是否前往设置授权？")
                    .setPositiveButton("去授权", (d, w) -> {
                        try {
                            Intent intent = new Intent(
                                    android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                    Uri.parse("package:" + getPackageName()));
                            startActivity(intent);
                        } catch (Exception e) {
                            startActivity(new Intent(android.provider.Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                        }
                    })
                    .setNegativeButton("稍后", null)
                    .show();
            return;
        }
        final List<DetectionResult> snapshot = new ArrayList<>(allResults);
        final File artifact = decodedDirectory;
        worker.execute(() -> {
            ResultExporter.SaveResult result = ResultExporter.saveAdvancedReport(
                    getApplicationContext(), snapshot, artifact);
            runOnUiThread(() -> {
                if (result.success) {
                    Toast.makeText(this, "结果已保存至: " + result.filePath, Toast.LENGTH_LONG).show();
                } else {
                    Toast.makeText(this, "保存失败: " + result.error, Toast.LENGTH_LONG).show();
                }
            });
        });
    }

    private void updateSummary(boolean complete) {
        int pass = 0, suspicious = 0, risk = 0;
        for (DetectionResult result : allResults) {
            if (result.status == DetectionStatus.PASS) pass++;
            else if (result.status == DetectionStatus.RISK) risk++;
            else suspicious++;
        }
        int verdictDotRes = R.drawable.bg_dot_neutral;
        if (mode == ReportRepository.Mode.ADVANCED) {
            int memFindings = 0, fileFindings = 0, memTotal = 0, fileTotal = 0;
            for (DetectionResult r : allResults) {
                if (r.id.startsWith("advanced.memscan")) {
                    memTotal++;
                    if (r.status == DetectionStatus.RISK) memFindings++;
                } else if (r.id.startsWith("advanced.file.") || r.id.startsWith("advanced.finding.")) {
                    fileTotal++;
                    if (r.status == DetectionStatus.RISK) fileFindings++;
                }
            }
            if (!complete) {
                binding.summaryTitle.setText("扫描进行中");
                binding.summaryDetail.setText("内存命中 " + memTotal + " 项 · 解密文件 " + fileTotal + " 项");
                return;
            }
            int totalFindings = memFindings + fileFindings;
            if (totalFindings > 0) {
                binding.summaryTitle.setText("环境异常 · 发现 " + totalFindings + " 项明确观察值");
                binding.summaryDetail.setText("内存扫描发现 " + memFindings + " 项 · 文件解密发现 " + fileFindings +
                        " 项\nACE 已读取到设备的环境信号，可能影响最终判定。");
                verdictDotRes = R.drawable.bg_dot_danger;
            } else if (suspicious > 0) {
                binding.summaryTitle.setText("环境待确认 · " + suspicious + " 项未决信号");
                binding.summaryDetail.setText("未发现明确异常观察值；存在 " + suspicious + " 项需要进一步确认的扫描结果。");
                verdictDotRes = R.drawable.bg_dot_warning;
            } else {
                binding.summaryTitle.setText("环境正常 · 未发现明确异常");
                binding.summaryDetail.setText("内存扫描与文件解密均未发现明确异常观察值。");
                verdictDotRes = R.drawable.bg_dot_success;
            }
            binding.verdictIndicator.setBackgroundResource(verdictDotRes);
            return;
        }
        if (!complete) {
            binding.summaryTitle.setText("已完成 " + allResults.size() + " 项");
            verdictDotRes = R.drawable.bg_dot_warning;
        } else if (risk > 0) {
            binding.summaryTitle.setText("设备存在明确风险信号");
            verdictDotRes = R.drawable.bg_dot_danger;
        } else if (suspicious > 0) {
            binding.summaryTitle.setText("设备存在未决环境信号");
            verdictDotRes = R.drawable.bg_dot_warning;
        } else {
            binding.summaryTitle.setText("设备环境正常");
            verdictDotRes = R.drawable.bg_dot_success;
        }
        binding.summaryDetail.setText("通过 " + pass + " · 可疑 " + suspicious + " · 风险 " + risk);
        binding.verdictIndicator.setBackgroundResource(verdictDotRes);
    }

    private void applyFilter(int filter) {
        List<DetectionResult> filtered = new ArrayList<>();
        for (DetectionResult r : allResults) {
            if (filter == 0) filtered.add(r);
            else if (filter == 1 && r.status == DetectionStatus.RISK) filtered.add(r);
            else if (filter == 2 && r.status == DetectionStatus.PASS) filtered.add(r);
        }
        adapter.submitItems(buildListItems(filtered, mode));
        binding.resultCountLabel.setText(filtered.size() + " 项");
    }

    private static boolean isFilteredOut(DetectionResult result) {
        if (result == null || result.title == null) return false;
        String t = result.title.toLowerCase(Locale.ROOT);
        return t.contains("大厅.zip") || t.contains("对局.zip") || t.contains("大厅前.zip");
    }

    private List<ListItem> buildListItems(List<DetectionResult> source, ReportRepository.Mode mode) {
        List<ListItem> items = new ArrayList<>();
        if (mode == ReportRepository.Mode.ADVANCED) {
            // Section 1: 内存特征点定位扫描 (v2.5 新增，首屏)
            List<DetectionResult> featureResults = new ArrayList<>();
            List<DetectionResult> memResults = new ArrayList<>();
            List<DetectionResult> fileResults = new ArrayList<>();
            List<DetectionResult> otherResults = new ArrayList<>();
            for (DetectionResult r : source) {
                if (r.id.startsWith("advanced.memscan.feature.")) featureResults.add(r);
                else if (r.id.startsWith("advanced.memscan")) memResults.add(r);
                else if (r.id.startsWith("advanced.file.") || r.id.startsWith("advanced.finding.")
                        || r.id.startsWith("advanced.observation.") || r.id.startsWith("advanced.runtime.")
                        || r.id.startsWith("advanced.classification") || r.id.startsWith("advanced.files.")
                        || r.id.startsWith("advanced.apk.") || r.id.startsWith("advanced.crypto.")
                        || r.id.startsWith("advanced.root") || r.id.startsWith("advanced.limit")) fileResults.add(r);
                else otherResults.add(r);
            }
            if (!featureResults.isEmpty()) {
                items.add(new SectionItem("内 存 特 征 点 扫 描", featureResults.size() + " 项", R.color.primary));
                for (DetectionResult r : featureResults) items.add(new ResultItem(r));
            }
            if (!memResults.isEmpty()) {
                items.add(new SectionItem("内 存 模 式 扫 描 结 果", memResults.size() + " 项", R.color.primary));
                for (DetectionResult r : memResults) items.add(new ResultItem(r));
            }
            if (!fileResults.isEmpty()) {
                items.add(new SectionItem("解 密 文 件 结 果", fileResults.size() + " 项", R.color.info));
                for (DetectionResult r : fileResults) items.add(new ResultItem(r));
            }
            if (!otherResults.isEmpty()) {
                items.add(new SectionItem("其 他 检 测", otherResults.size() + " 项", R.color.text_tertiary));
                for (DetectionResult r : otherResults) items.add(new ResultItem(r));
            }
        } else {
            if (!source.isEmpty()) {
                items.add(new SectionItem("检 测 结 果", source.size() + " 项", R.color.primary));
                for (DetectionResult r : source) items.add(new ResultItem(r));
            }
        }
        return items;
    }

    private void showDetail(DetectionResult result) {
        View content = getLayoutInflater().inflate(R.layout.dialog_detection_detail, null, false);
        TextView eyebrow = content.findViewById(R.id.detailEyebrow);
        TextView title = content.findViewById(R.id.detailTitle);
        TextView status = content.findViewById(R.id.detailStatus);
        TextView rawContent = content.findViewById(R.id.detailRawContent);
        TextView explanation = content.findViewById(R.id.detailExplanation);
        ScrollView scroll = content.findViewById(R.id.detailScroll);
        Button close = content.findViewById(R.id.detailClose);
        boolean advanced = mode == ReportRepository.Mode.ADVANCED;
        eyebrow.setText(advanced ? result.category.toUpperCase(Locale.ROOT) : "检 测 项");
        title.setText(result.title);
        String statusLabel = advanced
                ? result.status == DetectionStatus.PASS ? "已读取"
                : result.status == DetectionStatus.RISK ? "已发现" : "需要确认"
                : result.status.label;
        status.setText(statusLabel);
        status.setTextColor(result.status == DetectionStatus.RISK ? getColor(R.color.danger)
                : result.status == DetectionStatus.SUSPICIOUS ? getColor(R.color.warning)
                : getColor(R.color.success));
        DetailContent detail = buildDetailContent(result, advanced);
        rawContent.setText(detail.raw);
        explanation.setText(detail.explanation);
        scroll.getLayoutParams().height = Math.min(getResources().getDisplayMetrics().heightPixels * 65 / 100,
                (int) (640 * getResources().getDisplayMetrics().density));
        AlertDialog dialog = new AlertDialog.Builder(this).setView(content).create();
        close.setOnClickListener(v -> dialog.dismiss());
        dialog.show();
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            window.setLayout(Math.min(getResources().getDisplayMetrics().widthPixels - dp(32), dp(720)),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
        }
    }

    private static final class DetailContent {
        final String raw;
        final String explanation;
        DetailContent(String raw, String explanation) {
            this.raw = raw; this.explanation = explanation;
        }
    }

    private static DetailContent buildDetailContent(DetectionResult result, boolean advanced) {
        if (advanced) {
            return new DetailContent(advancedRawContent(result), advancedExplanation(result));
        }
        return new DetailContent(
                "检测详情（检查的路径 / 属性 / 系统调用）\n" + result.evidence +
                "\n\n模拟判定\n" + result.summary +
                "\n\nACE 判定标准\n" + result.rule +
                "\n\n证据置信度\n" + result.confidence + "%\n\n耗时\n" + result.durationMs + " ms",
                basicExplanation(result));
    }

    private static String advancedRawContent(DetectionResult result) {
        // Show full evidence without truncation
        StringBuilder sb = new StringBuilder();
        sb.append("扫描来源\n");
        sb.append(extractField(result.evidence, "扫描来源=", "文件=", "—")).append("\n\n");
        sb.append("扫描了\n");
        sb.append(extractField(result.evidence, "扫描了=", "—")).append("\n\n");
        sb.append("发现了\n");
        sb.append(extractField(result.evidence, "发现了=", "发现内容=", result.summary)).append("\n\n");
        sb.append("设备判定\n");
        sb.append(extractField(result.evidence, "设备判定=", "—")).append("\n\n");
        sb.append("上报结论\n");
        sb.append(extractField(result.evidence, "上报结论=", "—"));
        // Add full evidence appendix
        sb.append("\n\n────────────────\n完整证据字段\n");
        sb.append(result.evidence == null ? "—" : result.evidence);
        return sb.toString();
    }

    private static String extractField(String evidence, String... prefixes) {
        if (evidence == null) return "—";
        for (String prefix : prefixes) {
            for (String line : evidence.split("\\r?\\n")) {
                if (line.startsWith(prefix)) return line.substring(prefix.length()).trim();
            }
        }
        return "—";
    }

    private static String advancedExplanation(DetectionResult result) {
        String id = result.id;
        // v2.5: 内存特征点的智能解释
        if (id.startsWith("advanced.memscan.feature.")) {
            return featurePointExplanation(result);
        }
        // v2.5: 特征点扫描总览的智能解释
        if (id.equals("advanced.memscan.feature.summary")) {
            return "本项是特征点定位扫描的综合结论。\n\n"
                    + "说明\n" + result.summary + "\n\n"
                    + "扫描方法\n基于 IDA 逆向得到的 30+ 关键偏移，通过 /proc/[pid]/maps 实时解析模块基址（ASLR-aware），"
                    + "再用 process_vm_readv 系统调用读取每个特征点 64 字节内容，最后与已知干净环境的基线对比判定。\n\n"
                    + "判定逻辑\n"
                    + "· 正常 (pass)：代码段指令完整、数据段有合理内容、函数指针表未被篡改\n"
                    + "· 可疑 (suspicious)：全零填充、BRK 断点覆盖、模块未加载\n"
                    + "· 异常 (risk)：检测到 Hook 跳转指令 (LDR X16, =addr; BR X16)、"
                    + "函数指针表被篡改、反调试函数被 NOP 填充\n\n"
                    + "环境判断依据\n"
                    + "Hook 检测类特征点异常 = 第三方注入框架正在劫持 ACE 函数\n"
                    + "反调试类特征点异常 = 调试器或绕过工具正在干扰 ACE 反调试\n"
                    + "报告/加密类特征点异常 = 上报数据可能被篡改或伪造";
        }
        String file = extractField(result.evidence, "文件=", "扫描来源=");
        if (file.equals("—")) file = result.title;
        String name = file.toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder();
        sb.append("文件作用\n").append(purposeForFile(name)).append("\n\n");
        sb.append("ACE 检测中的角色\n").append(aceRoleForFile(name)).append("\n\n");
        sb.append("为何被检测\n").append(detectionReason(id, name)).append("\n\n");
        sb.append("环境判断\n").append(environmentJudgment(id, result));
        return sb.toString();
    }

    // v2.5: 内存特征点智能解释
    private static String featurePointExplanation(DetectionResult result) {
        String title = result.title;
        String evidence = result.evidence;
        String status = result.status.label;
        String reason = extractField(evidence, "设备判定=", "—");
        String hexContent = extractHexContent(evidence);
        String moduleName = title.contains(" · ") ? title.substring(0, title.indexOf(" · ")) : title;

        StringBuilder sb = new StringBuilder();
        sb.append("特征点定位\n");
        sb.append("该特征点位于 ").append(moduleName).append("，是 ACE 环境检测链中的关键位置。\n\n");

        sb.append("读取内容 (64 字节十六进制)\n");
        sb.append(hexContent.equals("—") ? "读取失败或模块未加载" : hexContent).append("\n\n");

        sb.append("基线对比结果\n");
        sb.append(reason).append("\n\n");

        sb.append("判定状态\n");
        sb.append(status).append("\n\n");

        sb.append("为何被扫描\n");
        sb.append(featurePointWhy(title)).append("\n\n");

        sb.append("环境含义\n");
        sb.append(featurePointEnvironment(title, result));

        return sb.toString();
    }

    private static String extractHexContent(String evidence) {
        if (evidence == null) return "—";
        int start = evidence.indexOf("读取内容(64字节 HEX)=\n");
        if (start < 0) return "—";
        start += "读取内容(64字节 HEX)=\n".length();
        int end = evidence.indexOf("\n设备判定=", start);
        if (end < 0) end = evidence.length();
        return evidence.substring(start, end).trim();
    }

    private static String featurePointWhy(String title) {
        String t = title.toLowerCase(Locale.ROOT);
        if (t.contains("rel_hook")) return "REL_HOOK 系列是 libtprt 的内联 Hook 函数，用于拦截系统调用和关键 API。扫描此处可以检测是否被二次 Hook。";
        if (t.contains("pfn_array") || t.contains("ori_array"))
            return "函数指针表保存了 ACE 拦截的系统函数地址。第三方工具会篡改此表以注入自定义逻辑。";
        if (t.contains("tp_syscall_imp")) return "直接 syscall 实现是 ACE 反 Hook 的关键点 - 绕过 PLT 表直接调用内核，可检测 PLT 层的 Hook。";
        if (t.contains("ptrace")) return "ptrace 调用点是反调试检测的核心 - ACE 用 ptrace 检查是否有调试器附加。";
        if (t.contains("unwind")) return "Unwind 信息查询用于栈回溯检测 - ACE 通过异常处理表检查调用栈完整性。";
        if (t.contains("tss_sdk") || t.contains("report")) return "TSS 报告接口负责生成和发送环境检测报告 - 扫描此处可确认报告链是否被篡改。";
        if (t.contains("xor") || t.contains("decrypt") || t.contains("key_provider"))
            return "XOR 解密函数和密钥提供者是 ACE 文件加密体系的核心 - 用于解密 ano_tmp 目录下的检测文件。";
        if (t.contains("cert") || t.contains("crt")) return "证书读取函数负责读取设备/客户端证书 - ACE 用此验证设备合法性。";
        if (t.contains("fingerprint") || t.contains("ksh")) return "指纹读取函数负责读取设备指纹 - ACE 用此识别设备唯一性。";
        if (t.contains("magic") || t.contains("string")) return "魔数字符串是 ACE 库的标识 - 51 处引用说明此字符串贯穿整个检测流程。";
        if (t.contains("version")) return "版本号字符串标识 ACE SDK 版本 - 用于规则匹配和兼容性检查。";
        if (t.contains("jni_onload")) return "JNI_OnLoad 是 libtprt 的入口函数 - 启用 ENABLE_OBJ_VM 标志，初始化整个检测框架。";
        if (t.contains("ue4") || t.contains("engine")) return "UE4 引擎关键点是 ACE 注入检测钩子的位置 - 监控游戏主循环和渲染流程。";
        if (t.contains("gpm")) return "GPM SDK 是腾讯反作弊 SDK 的入口 - 负责初始化反作弊环境和上报通道。";
        return "该特征点是 ACE 环境检测链中的关键位置，用于验证代码完整性。";
    }

    private static String featurePointEnvironment(String title, DetectionResult result) {
        if (result.status == DetectionStatus.RISK) {
            return "该项检测到异常信号 (Hook 篡改或反调试绕过)。\n"
                    + "这意味着第三方工具正在干扰 ACE 的检测逻辑，ACE 可能已记录此异常并准备上报。\n"
                    + "建议: 检查是否运行了 Frida/Xposed/EdXposed 等注入框架，或是否有调试器附加。";
        }
        if (result.status == DetectionStatus.SUSPICIOUS) {
            return "该项存在可疑信号 (代码被修改或模块未加载)。\n"
                    + "可能原因: 1) 目标进程未完全启动；2) 模块版本不匹配；3) 第三方工具进行了轻微修改。\n"
                    + "建议: 确保目标进程在前台运行，或重新扫描确认。";
        }
        return "该项内容正常，未检测到 Hook 篡改或反调试绕过。\n"
                + "ACE 的代码完整性良好，环境判定为正常。";
    }

    private static String basicExplanation(DetectionResult result) {
        return "检测项目\n" + result.title + "\n\n"
                + "模拟结果\n" + result.status.label + " · " + result.summary + "\n\n"
                + "对用户环境的最终影响\n" + basicImpact(result) + "\n\n"
                + "ACE 判定依据\n" + result.rule + "\n\n"
                + "置信度\n" + result.confidence + "%\n\n"
                + "说明\n本项 100% 还原 ACE SDK 对客户端环境的探测步骤，不读取目标进程内存，"
                + "仅在本地复现游戏运行时 ACE 会执行的检查逻辑并给出等同判定。";
    }

    private static String basicImpact(DetectionResult result) {
        if (result.status == DetectionStatus.RISK) {
            if (result.id.startsWith("root.")) return "若游戏 ACE 此时扫描，本机 Root 状态将被判定为命中，"
                    + "可能触发风控等级提升、坐标异常标记或限制对局匹配。";
            if (result.id.startsWith("emulator.") || result.id.startsWith("virtual.") || result.id.startsWith("cloud."))
                return "若游戏 ACE 此时扫描，本机将被识别为模拟器/云手机/虚拟环境，"
                    + "可能导致账号被标记为非真机环境并限制功能。";
            if (result.id.startsWith("boot.") || result.id.startsWith("oem.") || result.id.startsWith("verifiedboot."))
                return "若游戏 ACE 此时扫描，BL 解锁或 Verified Boot 异常将被上报，"
                    + "可能影响设备可信度评级。";
            if (result.id.startsWith("dev.") || result.id.startsWith("adb."))
                return "若游戏 ACE 此时扫描，开发者模式或 ADB 调试状态将被记录，"
                    + "可能被视为调试环境并降低设备信任分。";
            if (result.id.startsWith("risk.") || result.id.startsWith("dual."))
                return "若游戏 ACE 此时扫描，风险应用或多开环境将被检出，"
                    + "可能触发应用列表上报与对应风控策略。";
            return "若游戏 ACE 此时扫描，该项将被判定为风险并参与综合设备分类。";
        }
        if (result.status == DetectionStatus.SUSPICIOUS) {
            return "当前信号未决：ACE 可能继续在运行时补充探测后再做最终判定。"
                    + "建议消除可疑来源后再进入对局，避免被标记为待确认环境。";
        }
        return "该项未发现明确异常，ACE 在对应检查项上不会产生命中信号，"
                + "不构成本机环境的风险证据。";
    }

    private static String purposeForFile(String name) {
        if (name.contains("mrpcs_a_v")) return "保存 ACE 要执行的环境扫描规则（变体 V）。";
        if (name.contains("mrpcs_a_f")) return "保存 ACE 要执行的环境扫描规则（变体 F）。";
        if (name.contains("mrpcs_a_c")) return "保存另一组环境扫描规则和文字说明。";
        if (name.contains("mrpcs_a.data")) return "保存环境扫描规则主镜像。";
        if (name.startsWith("config2") || name.startsWith("config3")) return "保存不同版本要加载的规则文件及对应校验值。";
        if (name.contains("kvcache8")) return "保存 ACE 已写下的阶段性设备画像。";
        if (name.contains("ano_rdp")) return "保存设备指纹的摘要值。";
        if (name.contains("ano.i.m")) return "保存设备标识值。";
        if (name.contains("ano.ano3")) return "保存一组环境记录。";
        if (name.contains("comm.dat") || name.contains("comm.zip")) return "保存检测开关和能力名称。";
        if (name.contains("mpmc")) return "保存 ACE 处理过的记录及完整性校验。";
        if (name.contains("ano_app_915c")) return "保存客户端环境校验值。";
        if (name.contains("rcu.o")) return "保存更新状态和附加信息。";
        if (name.contains("tersafe.update")) return "保存检测组件的更新标记。";
        if (name.contains("h_rcd")) return "保存启动或阶段记录。";
        if (name.contains("up_cache") || name.contains("speedupcch")) return "保存组件缓存和运行阶段信息。";
        if (name.contains("ace_shell_db")) return "保存 ACE Shell 的本地记录。";
        if (name.contains("kmc.dat")) return "保存 ACE 可检查的设备节点和内核能力名称。";
        if (name.contains("mn_cache")) return "保存本轮加载或登记的组件库名称。";
        if (name.contains("crt.i2")) return "保存设备或客户端证书记录。";
        if (name.contains("ano_ksh")) return "保存内核 shell 或辅助环境信息。";
        if (name.contains("bmc.dat")) return "保存辅助环境采集信息。";
        if (name.contains("ace_cache_db")) return "保存 ACE 缓存数据库。";
        if (name.contains("tdm_cache")) return "保存 TDM 缓存数据。";
        if (name.contains("atti_obv")) return "保存观察类附加信息。";
        if (name.contains("cache_crc") || name.contains("cache_md5")) return "保存缓存校验值。";
        if (name.contains("cpcah")) return "保存附加缓存。";
        if (name.contains("ms_") && name.contains("_tmp")) return "保存扫描规则的临时分片。";
        if (name.contains("runtime_session")) return "保存目标应用运行期间的进程状态、文件哈希变化和只读快照。";
        if (name.contains("libtersafe")) return "ACE 主检测库，包含环境检测、内存扫描、报告生成与上报链。";
        if (name.contains("memscan")) return "目标进程内存扫描结果，包含双路扫描命中的所有特征点。";
        return "ACE 运行时创建或读取的辅助文件；已保留原始内容供分析。";
    }

    private static String aceRoleForFile(String name) {
        if (name.contains("mrpcs") || name.startsWith("config")) return "决定 ACE 检查哪些环境项目，是规则镜像本体。";
        if (name.contains("kvcache") || name.contains("ano_rdp") || name.contains("ano.i.m") || name.contains("mpmc"))
            return "记录 ACE 从设备上读到的内容，供后续上报或复查使用。";
        if (name.contains("comm")) return "决定哪些检查开关和能力被启用。";
        if (name.contains("apk")) return "只提供安装包静态线索，不代表本机已经命中。";
        if (name.contains("runtime_session")) return "提供检测文件在大厅和对局流程中的变化证据。";
        if (name.contains("libtersafe") && name.contains("运行时接口")) return "承载最终环境事件和待发送报告；实际字段以捕获到的缓冲区为准。";
        if (name.contains("ano_app") || name.contains("rcu") || name.contains("tersafe"))
            return "保存客户端环境状态或组件状态。";
        if (name.contains("memscan")) return "提供 ACE 在内存中实时扫描的特征点数据。";
        if (name.contains("crt") || name.contains("cert")) return "保存设备或客户端证书相关记录。";
        if (name.contains("kmc")) return "保存 ACE 可检查的设备节点和内核能力清单。";
        return "属于 ACE 环境检测的辅助记录，不能单独代表风险结论。";
    }

    private static String detectionReason(String id, String name) {
        if (id.startsWith("advanced.memscan.root")) return "目标进程内存中扫描到 Root/KernelSU/Magisk 相关字符串或路径，说明 ACE 在运行时已加载对应扫描规则。";
        if (id.startsWith("advanced.memscan.frida")) return "目标进程内存中扫描到 Frida 注入相关字符串，说明 ACE 可能识别到注入框架特征。";
        if (id.startsWith("advanced.memscan.xposed")) return "目标进程内存中扫描到 Xposed/LSPosed 相关字符串，说明 ACE 可能识别到框架注入特征。";
        if (id.startsWith("advanced.memscan.hook")) return "目标进程内存中扫描到 Hook 相关字符串，说明 ACE 可能识别到函数劫持特征。";
        if (id.startsWith("advanced.memscan.boot")) return "目标进程内存中扫描到 BL 解锁或 Verified Boot 相关数据，说明 ACE 在运行时检查了启动状态。";
        if (id.startsWith("advanced.memscan.cert")) return "目标进程内存中扫描到证书相关数据，说明 ACE 在运行时检查了设备或客户端证书。";
        if (id.startsWith("advanced.memscan.fingerprint")) return "目标进程内存中扫描到设备指纹相关数据，说明 ACE 在运行时读取了设备标识。";
        if (id.startsWith("advanced.memscan.report")) return "目标进程内存中扫描到 TSS 报告相关数据，说明 ACE 的报告生成或发送链正在运行。";
        if (id.startsWith("advanced.memscan")) return "目标进程内存中扫描到 ACE 检测相关数据。";
        if (id.startsWith("advanced.finding.root")) return "解码文件中包含明确 Root 画像事件，ACE 已将本机 Root 状态持久化到文件。";
        if (id.startsWith("advanced.finding.boot")) return "解码文件中包含 BL 解锁或 Verified Boot 状态信息。";
        if (id.startsWith("advanced.finding.fingerprint")) return "解码文件中保存了设备指纹摘要，ACE 已读取本机指纹。";
        if (id.startsWith("advanced.finding.certificate")) return "解码文件中保存了证书记录，ACE 已检查本机证书。";
        if (id.startsWith("advanced.finding.device_key")) return "解码文件或规则中提到设备密钥/序列号读取能力。";
        if (id.startsWith("advanced.finding.packages")) return "MRPCS 规则镜像中包含包、文件、进程扫描规则，ACE 会按这些规则检查本机。";
        if (id.startsWith("advanced.finding.upload")) return "已采集文件中未提供完整的明文上报包，需结合 TSS 报告接口数据确认。";
        if (id.startsWith("advanced.finding.coordinate")) return "尚未在持久文件中恢复环境判定到坐标销毁的关联字段。";
        if (id.startsWith("advanced.runtime.report")) return "ACE 的 TSS 报告接口在 IDA 中已确认存在调用链；接口存在与实际取得报告负载是独立证据。";
        if (id.startsWith("advanced.runtime.session")) return "记录目标应用是否运行、文件何时变化，并保存变化前后的只读副本。";
        if (id.startsWith("advanced.files.summary")) return "本轮共处理的文件清单（同一文件经多个 Root 目录别名出现时只计算一次）。";
        if (id.startsWith("advanced.file.")) return "ACE 已读取该文件并按已验证格式解码；具体内容以原始解密内容为准。";
        if (id.startsWith("advanced.apk")) return "只读取安装包静态文件名，寻找规则或本地结果文件。";
        if (id.startsWith("advanced.crypto")) return "已验证文件族使用静态、按格式区分的变换（XOR、CRC、ZIP 容器）。";
        if (id.startsWith("advanced.classification")) return "完整解码的综合结论，仅汇总明确画像观察或事件值。";
        return "该项属于 ACE 检测链的一部分；具体内容以原始解密内容为准。";
    }

    private static String environmentJudgment(String id, DetectionResult result) {
        if (result.status == DetectionStatus.RISK) {
            return "该项已确认为风险观察值，应作为环境异常信号计入综合判断。"
                    + "具体是否被服务端标记为命中，仍需结合 TSS 报告接口与最终上报字段确认。";
        }
        if (result.status == DetectionStatus.SUSPICIOUS) {
            return "该项为未决信号：文件已读取或字段已发现，但缺少明确命中值。"
                    + "需要后续轮次或运行时接口补充证据后才能闭合判定。";
        }
        return "该项当前未呈现明确异常观察值。规则能力字符串或文件存在不等于本机已命中。";
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void exportReport() {
        final ReportRepository.Mode exportMode = mode;
        final List<DetectionResult> exportResults = new ArrayList<>(allResults);
        worker.execute(() -> {
            try {
                ReportRepository repository = new ReportRepository();
                File file = repository.write(getApplicationContext(), exportMode, exportResults);
                File shareFile = file;
                if (exportMode == ReportRepository.Mode.ADVANCED && decodedDirectory != null) {
                    shareFile = repository.writeAdvancedBundle(getApplicationContext(), file, decodedDirectory);
                }
                File finalShareFile = shareFile;
                runOnUiThread(() -> { reportFile = file; repository.share(this, finalShareFile); });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "报告生成失败：" + e.getMessage(), Toast.LENGTH_LONG).show());
            }
        });
    }

    private void showAbout() {
        View content = getLayoutInflater().inflate(R.layout.dialog_detection_detail, null, false);
        TextView eyebrow = content.findViewById(R.id.detailEyebrow);
        TextView title = content.findViewById(R.id.detailTitle);
        TextView status = content.findViewById(R.id.detailStatus);
        TextView rawContent = content.findViewById(R.id.detailRawContent);
        TextView explanation = content.findViewById(R.id.detailExplanation);
        ScrollView scroll = content.findViewById(R.id.detailScroll);
        Button close = content.findViewById(R.id.detailClose);
        eyebrow.setText("关 于");
        title.setText(getString(R.string.app_name) + " " + getString(R.string.version));
        status.setText("更 新 日 志");
        status.setTextColor(getColor(R.color.primary));
        rawContent.setText(getString(R.string.about_changelog).replace("\\n", "\n"));
        explanation.setText("本版本新增高级模式结果本地持久化、基础模式 100% 还原 ACE 真实客户端环境检测，"
                + "并采用全新极简风自适应图标设计。");
        scroll.getLayoutParams().height = Math.min(getResources().getDisplayMetrics().heightPixels * 70 / 100,
                (int) (720 * getResources().getDisplayMetrics().density));
        AlertDialog dialog = new AlertDialog.Builder(this).setView(content).create();
        close.setOnClickListener(v -> dialog.dismiss());
        dialog.show();
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            window.setLayout(Math.min(getResources().getDisplayMetrics().widthPixels - dp(32), dp(720)),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
        }
    }

    private void showHome() {
        if (scanRunning) {
            scanGeneration++;
            if (activeTask != null) activeTask.cancel(true);
            scanRunning = false;
            Toast.makeText(this, "本次扫描已取消", Toast.LENGTH_SHORT).show();
        }
        binding.resultsPanel.setVisibility(View.GONE); binding.homePanel.setVisibility(View.VISIBLE);
        binding.homePanel.setAlpha(0f); binding.homePanel.animate().alpha(1f).setDuration(180).start();
    }

    @Override protected void onDestroy() {
        scanGeneration++;
        liveHandler.removeCallbacks(livePollTask);
        if (activeTask != null) activeTask.cancel(true);
        worker.shutdownNow();
        super.onDestroy();
    }
}
