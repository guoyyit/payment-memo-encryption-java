package com.github.guoyyit.paymentmemoencryptionjava.tests;

import com.github.guoyyit.paymentmemoencryptionjava.crypto.Envelope;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoCrypto;
import com.github.guoyyit.paymentmemoencryptionjava.keystore.PayeeKeyStore;
import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class CryptoTest {

    private final MemoCrypto crypto = new MemoCrypto();

    private PayeeKeyStore storeWithGeneration(long genId) {
        PayeeKeyStore store = new PayeeKeyStore("alice");
        store.rotate();
        return store;
    }

    @Test
    void roundtripRecoversPlaintextAndGeneration() {
        PayeeKeyStore store = storeWithGeneration(1L);
        byte[] envelope = crypto.encrypt("alice", 1L, store.getActive().getPublicKey(), "hello memo");

        MemoCrypto.DecryptOutcome outcome = crypto.decrypt("alice", store, envelope);

        assertEquals(MemoCrypto.Status.RECOVERED, outcome.getStatus());
        assertEquals("hello memo", outcome.getPlaintext());
        assertEquals(1L, outcome.getKeyGenId());
    }

    @Test
    void decryptWithWrongKeyFails() {
        PayeeKeyStore alice = storeWithGeneration(1L);
        PayeeKeyStore bob = storeWithGeneration(1L);
        byte[] envelope = crypto.encrypt("alice", 1L, alice.getActive().getPublicKey(), "secret");

        MemoCrypto.DecryptOutcome outcome = crypto.decrypt("alice", bob, envelope);

        assertEquals(MemoCrypto.Status.DECRYPTION_FAILED, outcome.getStatus());
    }

    @Test
    void tamperedCiphertextIsRejected() {
        PayeeKeyStore store = storeWithGeneration(1L);
        byte[] envelope = crypto.encrypt("alice", 1L, store.getActive().getPublicKey(), "secret");
        envelope[envelope.length - 1] ^= 0x01;

        MemoCrypto.DecryptOutcome outcome = crypto.decrypt("alice", store, envelope);

        assertEquals(MemoCrypto.Status.DECRYPTION_FAILED, outcome.getStatus());
    }

    @Test
    void unknownGenerationIsDistinguishable() {
        PayeeKeyStore store = storeWithGeneration(1L);
        byte[] envelope = crypto.encrypt("alice", 99L, store.getActive().getPublicKey(), "secret");

        MemoCrypto.DecryptOutcome outcome = crypto.decrypt("alice", store, envelope);

        assertEquals(MemoCrypto.Status.UNKNOWN_GENERATION, outcome.getStatus());
    }

    @Test
    void truncatedEnvelopeIsMalformed() {
        PayeeKeyStore store = storeWithGeneration(1L);
        byte[] envelope = crypto.encrypt("alice", 1L, store.getActive().getPublicKey(), "secret");
        byte[] truncated = new byte[20];
        System.arraycopy(envelope, 0, truncated, 0, 20);

        MemoCrypto.DecryptOutcome outcome = crypto.decrypt("alice", store, truncated);

        assertEquals(MemoCrypto.Status.MALFORMED, outcome.getStatus());
    }

    @Test
    void envelopeForOtherPayeeIsSkipped() {
        PayeeKeyStore store = storeWithGeneration(1L);
        byte[] envelope = crypto.encrypt("bob", 1L, store.getActive().getPublicKey(), "secret");

        MemoCrypto.DecryptOutcome outcome = crypto.decrypt("alice", store, envelope);

        assertEquals(MemoCrypto.Status.NOT_FOR_PAYEE, outcome.getStatus());
    }

    @Test
    void differentMemosGetDifferentEnvelopes() {
        PayeeKeyStore store = storeWithGeneration(1L);
        byte[] first = crypto.encrypt("alice", 1L, store.getActive().getPublicKey(), "a");
        byte[] second = crypto.encrypt("alice", 1L, store.getActive().getPublicKey(), "a");

        // random IV and ephemeral key make envelopes distinct, but both decrypt
        MemoCrypto.DecryptOutcome firstOutcome = crypto.decrypt("alice", store, first);
        MemoCrypto.DecryptOutcome secondOutcome = crypto.decrypt("alice", store, second);
        assertEquals(MemoCrypto.Status.RECOVERED, firstOutcome.getStatus());
        assertEquals(MemoCrypto.Status.RECOVERED, secondOutcome.getStatus());
        assertEquals(firstOutcome.getPlaintext(), secondOutcome.getPlaintext());
        assertFalse(java.util.Arrays.equals(first, second));
    }
}
