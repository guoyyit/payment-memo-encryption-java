package com.github.guoyyit.paymentmemoencryptionjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "memo")
public class MemoProperties {

    private int maxLength = 4096;
    private int maxMemosPerTransfer = 20;
    private int scanBatchSize = 50;
    private String dataDir = "./data";

    public int getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(int maxLength) {
        this.maxLength = maxLength;
    }

    public int getMaxMemosPerTransfer() {
        return maxMemosPerTransfer;
    }

    public void setMaxMemosPerTransfer(int maxMemosPerTransfer) {
        this.maxMemosPerTransfer = maxMemosPerTransfer;
    }

    public int getScanBatchSize() {
        return scanBatchSize;
    }

    public void setScanBatchSize(int scanBatchSize) {
        this.scanBatchSize = scanBatchSize;
    }

    public String getDataDir() {
        return dataDir;
    }

    public void setDataDir(String dataDir) {
        this.dataDir = dataDir;
    }
}
