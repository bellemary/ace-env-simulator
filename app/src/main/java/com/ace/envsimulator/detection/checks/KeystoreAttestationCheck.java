package com.ace.envsimulator.detection.checks;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public final class KeystoreAttestationCheck extends BaseCheck {
    private static final String ALIAS = "ANO_KEYSTORE_ALIAS_03_23";
    public KeystoreAttestationCheck() { super("keystore.attestation", "设备证书", "AndroidKeyStore 硬件证明链"); }

    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        try {
            byte[] challenge = new byte[64];
            if (Build.VERSION.SDK_INT >= 26) SecureRandom.getInstanceStrong().nextBytes(challenge);
            else SecureRandom.getInstance("SHA1PRNG").nextBytes(challenge);
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            Certificate[] chain = store.getCertificateChain(ALIAS);
            if (chain == null || chain.length == 0) {
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                        .setAttestationChallenge(challenge)
                        .setKeySize(2048)
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                generator.initialize(spec);
                generator.generateKeyPair();
                chain = store.getCertificateChain(ALIAS);
            }
            if (chain == null || chain.length == 0) return suspicious(start, "未取得本应用 UID 的证明证书链", "alias=" + ALIAS,
                    "RSA-2048/PKCS1/SHA-256+SHA-1/64-byte challenge", 92);
            StringBuilder evidence = new StringBuilder("alias=").append(ALIAS).append("\nchain_length=").append(chain.length);
            for (int i = 0; i < chain.length; i++) {
                evidence.append("\n#").append(i).append(" sha256=").append(CheckSupport.sha256(chain[i].getEncoded()));
                if (chain[i] instanceof X509Certificate) {
                    X509Certificate cert = (X509Certificate) chain[i];
                    evidence.append("\n issuer=").append(cert.getIssuerX500Principal().getName());
                    evidence.append("\n subject=").append(cert.getSubjectX500Principal().getName());
                }
            }
            return suspicious(start, "已取得本应用 UID 的证书链，目标名单分类仍未知", evidence +
                    "\ncontext_limit=AndroidKeyStore 按 UID 隔离；设备画像 VM 另出现 ANO_KEYSTORE_ALIAS_0306",
                    "客户端 att_cert 白/黑名单来自运行时配置；本应用链不等于目标包证书链", 96);
        } catch (Exception e) {
            return suspicious(start, "本应用硬件证明生成或读取失败", e.getClass().getSimpleName() + ": " + e.getMessage(),
                    "复现 RSA/AndroidKeyStore/attestation challenge 参数", 90);
        }
    }
}
