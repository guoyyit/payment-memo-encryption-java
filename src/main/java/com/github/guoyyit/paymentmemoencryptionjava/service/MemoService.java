package com.github.guoyyit.paymentmemoencryptionjava.service;

import com.github.guoyyit.paymentmemoencryptionjava.config.MemoProperties;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoCrypto;
import com.github.guoyyit.paymentmemoencryptionjava.dto.CreateTransferRequest;
import com.github.guoyyit.paymentmemoencryptionjava.keystore.KeyGeneration;
import com.github.guoyyit.paymentmemoencryptionjava.keystore.PayeeKeyStore;
import com.github.guoyyit.paymentmemoencryptionjava.scan.MemoScanner;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Memo;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Transfer;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.TransferStore;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Application service wiring key management, transfer creation and scanning.
 */
@Service
public class MemoService {

    private final MemoProperties properties;
    private final MemoCrypto crypto = new MemoCrypto();
    private final Map<String, PayeeKeyStore> keyStores = new ConcurrentHashMap<>();

    private Path dataDir;
    private TransferStore store;

    public MemoService(MemoProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        this.dataDir = Path.of(properties.getDataDir());
        this.store = new TransferStore(dataDir.resolve("stream"));
    }

    /**
     * Resets the service to use the given data directory (for testing).
     */
    public void reset(Path dataDir) {
        this.dataDir = dataDir;
        this.store = new TransferStore(dataDir.resolve("stream"));
        keyStores.clear();
    }

    /**
     * Rotates the active key generation for a payee.
     */
    public KeyGeneration rotateKey(String payeeId) {
        PayeeKeyStore keyStore = keyStore(payeeId);
        KeyGeneration generation = keyStore.rotate();
        keyStore.save(keyStoreFile(payeeId));
        return generation;
    }

    /**
     * Creates a transfer, encrypting every memo to the payee's active
     * generation. Rejects over-limit requests deterministically.
     */
    public Transfer createTransfer(CreateTransferRequest request) {
        validate(request);
        PayeeKeyStore keyStore = keyStore(request.getToPayeeId());
        KeyGeneration active = keyStore.getActive();

        Transfer transfer = new Transfer();
        transfer.setRequestId(request.getRequestId());
        transfer.setFromPayeeId(request.getFromPayeeId());
        transfer.setToPayeeId(request.getToPayeeId());
        for (int i = 0; i < request.getMemos().size(); i++) {
            String plaintext = request.getMemos().get(i);
            byte[] envelope = crypto.encrypt(request.getToPayeeId(), active.getGenId(),
                    active.getPublicKey(), plaintext);
            transfer.getMemos().add(new Memo(i, envelope));
        }
        return store.commit(transfer);
    }

    /**
     * Scans the committed stream for memos addressed to the payee.
     */
    public ScanResult scan(String payeeId) {
        PayeeKeyStore keyStore = keyStore(payeeId);
        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                checkpointFile(payeeId), properties.getScanBatchSize());
        return scanner.scan();
    }

    /**
     * Exports the payee's key generations encrypted with a password.
     */
    public String exportKeys(String payeeId, char[] password) {
        PayeeKeyStore keyStore = keyStore(payeeId);
        return Base64.getEncoder().encodeToString(keyStore.exportEncrypted(password));
    }

    /**
     * Imports key generations from an encrypted bundle, replacing the payee's
     * current store.
     */
    public void importKeys(String payeeId, String bundleBase64, char[] password) {
        byte[] bundle = Base64.getDecoder().decode(bundleBase64);
        PayeeKeyStore imported = PayeeKeyStore.importEncrypted(bundle, password);
        if (!payeeId.equals(imported.getPayeeId())) {
            throw new IllegalArgumentException("bundle payeeId mismatch");
        }
        imported.save(keyStoreFile(payeeId));
        keyStores.put(payeeId, imported);
    }

    private void validate(CreateTransferRequest request) {
        if (request.getRequestId() == null || request.getRequestId().isBlank()) {
            throw new IllegalArgumentException("requestId required");
        }
        if (request.getFromPayeeId() == null || request.getFromPayeeId().isBlank()) {
            throw new IllegalArgumentException("fromPayeeId required");
        }
        if (request.getToPayeeId() == null || request.getToPayeeId().isBlank()) {
            throw new IllegalArgumentException("toPayeeId required");
        }
        if (request.getMemos() == null || request.getMemos().isEmpty()) {
            throw new IllegalArgumentException("at least one memo required");
        }
        if (request.getMemos().size() > properties.getMaxMemosPerTransfer()) {
            throw new IllegalArgumentException("too many memos: " + request.getMemos().size()
                    + " > " + properties.getMaxMemosPerTransfer());
        }
        for (String memo : request.getMemos()) {
            if (memo == null || memo.length() > properties.getMaxLength()) {
                throw new IllegalArgumentException("memo too long: "
                        + (memo == null ? 0 : memo.length()) + " > " + properties.getMaxLength());
            }
        }
    }

    private PayeeKeyStore keyStore(String payeeId) {
        return keyStores.computeIfAbsent(payeeId, id -> {
            Path file = keyStoreFile(id);
            if (java.nio.file.Files.exists(file)) {
                return PayeeKeyStore.load(file);
            }
            return new PayeeKeyStore(id);
        });
    }

    private Path keyStoreFile(String payeeId) {
        return dataDir.resolve("keys").resolve(payeeId + ".json");
    }

    private Path checkpointFile(String payeeId) {
        return dataDir.resolve("checkpoints").resolve(payeeId + ".checkpoint");
    }
}
