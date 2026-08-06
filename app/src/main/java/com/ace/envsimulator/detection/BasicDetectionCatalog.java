package com.ace.envsimulator.detection;

import com.ace.envsimulator.detection.checks.AdbEnvironmentCheck;
import com.ace.envsimulator.detection.checks.BootloaderCheck;
import com.ace.envsimulator.detection.checks.CloudDeviceCheck;
import com.ace.envsimulator.detection.checks.DeveloperOptionsCheck;
import com.ace.envsimulator.detection.checks.EmulatorArtifactCheck;
import com.ace.envsimulator.detection.checks.FingerprintConsistencyCheck;
import com.ace.envsimulator.detection.checks.JavaRootCheck;
import com.ace.envsimulator.detection.checks.KeystoreAttestationCheck;
import com.ace.envsimulator.detection.checks.MediaDrmIdentityCheck;
import com.ace.envsimulator.detection.checks.OemUnlockCheck;
import com.ace.envsimulator.detection.checks.RiskPackageProcessCheck;
import com.ace.envsimulator.detection.checks.RootProbeChecks;
import com.ace.envsimulator.detection.checks.RootAggregationConfigCheck;
import com.ace.envsimulator.detection.checks.SelinuxCheck;
import com.ace.envsimulator.detection.checks.VerifiedBootCheck;
import com.ace.envsimulator.detection.checks.VirtualizationCheck;
import com.ace.envsimulator.detection.checks.VendorRootPropertiesCheck;
import com.ace.envsimulator.detection.checks.BootHistoryCheck;
import com.ace.envsimulator.detection.checks.BootPartitionCheck;
import com.ace.envsimulator.detection.checks.VirtPipeCheck;
import com.ace.envsimulator.detection.checks.TargetAppIdentityCheck;
import com.ace.envsimulator.detection.checks.DualAppEnvironmentCheck;
import com.ace.envsimulator.detection.checks.FrameworkEnvironmentCheck;
import java.util.ArrayList;
import java.util.List;

public final class BasicDetectionCatalog {
    private BasicDetectionCatalog() {}
    public static List<DetectionCheck> create() {
        List<DetectionCheck> checks = new ArrayList<>();
        checks.addAll(RootProbeChecks.create());
        checks.add(new RootAggregationConfigCheck());
        checks.add(new JavaRootCheck());
        checks.add(new BootloaderCheck());
        checks.add(new VerifiedBootCheck());
        checks.add(new OemUnlockCheck());
        checks.add(new DeveloperOptionsCheck());
        checks.add(new AdbEnvironmentCheck());
        checks.add(new SelinuxCheck());
        checks.add(new FingerprintConsistencyCheck());
        checks.add(new VendorRootPropertiesCheck());
        checks.add(new BootHistoryCheck());
        checks.add(new BootPartitionCheck());
        checks.add(new VirtPipeCheck());
        checks.add(new TargetAppIdentityCheck());
        checks.add(new CloudDeviceCheck());
        checks.add(new EmulatorArtifactCheck());
        checks.add(new VirtualizationCheck());
        checks.add(new RiskPackageProcessCheck());
        checks.add(new DualAppEnvironmentCheck());
        checks.add(new FrameworkEnvironmentCheck());
        checks.add(new KeystoreAttestationCheck());
        checks.add(new MediaDrmIdentityCheck());
        return checks;
    }
}
