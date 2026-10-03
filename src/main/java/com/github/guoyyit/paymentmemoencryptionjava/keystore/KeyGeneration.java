package com.github.guoyyit.paymentmemoencryptionjava.keystore;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

/**
 * A payee key generation placeholder.
 */
public class KeyGeneration {

    public enum Status {
        ACTIVE,
        RETIRED
    }

    private long genId;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Status status;
    private Instant createdAt;

    public long getGenId() {
        return genId;
    }

    public void setGenId(long genId) {
        this.genId = genId;
    }

    @JsonIgnore
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @JsonIgnore
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
