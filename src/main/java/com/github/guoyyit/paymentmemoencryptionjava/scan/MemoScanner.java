package com.github.guoyyit.paymentmemoencryptionjava.scan;

import com.github.guoyyit.paymentmemoencryptionjava.config.LimitConfig;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.KeyGeneration;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.KeyManager;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoDecryptionException;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoIntegrityException;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoCipher;
import com.github.guoyyit.paymentmemoencryptionjava.domain.EncryptedMemo;
import com.github.guoyyit.paymentmemoencryptionjava.domain.Transfer;
import com.github.guoyyit.paymentmemoencryptionjava.stream.LogSlice;
import com.github.guoyyit.paymentmemoencryptionjava.stream.TransferLog;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Scans the append-only transfer stream for one recipient in transfer-sequence order.
 *
 * <p>Scanning is deterministic and cursor based. {@link #scanBatch(String)} never mutates
 * the durable cursor: the caller receives the outcomes plus the next position and only
 * acknowledges it with {@link #commit(String, ScanPosition)} after the recovered memos are
 * durable on the consumer side. A crash therefore resumes from the last committed
 * position, and the output of any batch is solely a function of (stream, position),
 * independent of previous batch boundaries.
 *
 * <p>Memos addressed to other recipients are skipped. Failures are reported with a
 * distinguishable {@link FailureReason} and never stop the scan: every memo, including a
 * failing one, advances the cursor by its transfer.
 */
public class MemoScanner {

    private final KeyManager keyManager;
    private final TransferLog transferLog;
    private final CursorStore cursorStore;
    private final LimitConfig config;
    private final MemoCipher memoCipher;

    public MemoScanner(KeyManager keyManager, MemoCipher memoCipher, TransferLog transferLog,
                       CursorStore cursorStore, LimitConfig config) {
        this.keyManager = keyManager;
        this.transferLog = transferLog;
        this.cursorStore = cursorStore;
        this.config = config;
        this.memoCipher = memoCipher;
    }

    public ScanOutcome scanBatch(String recipientId) {
        return scanBatch(recipientId, cursorStore.load(recipientId));
    }

    public ScanOutcome scanBatch(String recipientId, ScanPosition fromPosition) {
        LogSlice slice = transferLog.readSlice(fromPosition.nextOffset(), config.scanBatchSize());
        List<RecoveredMemo> recovered = new ArrayList<>();
        List<ScanFailure> failures = new ArrayList<>();

        long sequence = fromPosition.nextSequence();
        long offset = fromPosition.nextOffset();
        for (Transfer transfer : slice.transfers()) {
            scanTransfer(recipientId, transfer, recovered, failures);
            sequence = transfer.sequence();
        }
        long nextOffset = slice.nextOffset();
        ScanPosition nextPosition = new ScanPosition(
                slice.transfers().isEmpty() ? sequence : lastSequence(slice), nextOffset);
        boolean hasMore = nextOffset < transferLog.lengthBytes();
        return new ScanOutcome(List.copyOf(recovered), List.copyOf(failures), nextPosition, hasMore);
    }

    public void commit(String recipientId, ScanPosition position) {
        cursorStore.store(recipientId, position);
    }

    private void scanTransfer(String recipientId, Transfer transfer,
                              List<RecoveredMemo> recovered, List<ScanFailure> failures) {
        List<EncryptedMemo> memos = transfer.memos();
        for (int index = 0; index < memos.size(); index++) {
            EncryptedMemo memo = memos.get(index);
            if (!recipientId.equals(memo.recipientId())) {
                continue;
            }
            KeyGeneration key = keyManager.key(recipientId, memo.keyGeneration());
            if (key == null) {
                failures.add(new ScanFailure(transfer.sequence(), index, recipientId,
                        memo.keyGeneration(), FailureReason.UNKNOWN_KEY_GENERATION));
                continue;
            }
            try {
                byte[] plaintext = memoCipher.open(memo, key, transfer.sequence(), index);
                recovered.add(new RecoveredMemo(transfer.sequence(), index, recipientId,
                        memo.keyGeneration(), new String(plaintext, StandardCharsets.UTF_8)));
            } catch (MemoIntegrityException e) {
                failures.add(new ScanFailure(transfer.sequence(), index, recipientId,
                        memo.keyGeneration(), FailureReason.INTEGRITY_FAILED));
            } catch (MemoDecryptionException e) {
                failures.add(new ScanFailure(transfer.sequence(), index, recipientId,
                        memo.keyGeneration(), FailureReason.DECRYPTION_FAILED));
            }
        }
    }

    private static long lastSequence(LogSlice slice) {
        List<Transfer> transfers = slice.transfers();
        return transfers.get(transfers.size() - 1).sequence();
    }
}
