package com.github.guoyyit.paymentmemoencryptionjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.paymentmemoencryptionjava.dto.CreateTransferRequest;
import com.github.guoyyit.paymentmemoencryptionjava.scan.RecoveredMemo;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class ApplicationTests2 {

    private static final Path DATA_DIR = Path.of("target", "test-data2");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private com.github.guoyyit.paymentmemoencryptionjava.service.MemoService memoService;

    @BeforeEach
    void setUp() throws Exception {
        System.out.println("DEBUG: BeforeEach running, dataDir exists=" + Files.exists(DATA_DIR));
        deleteRecursively(DATA_DIR);
        memoService.reset(DATA_DIR);
    }

    private static void deleteRecursively(Path path) throws Exception {
        if (!Files.exists(path)) {
            return;
        }
        try (var walk = Files.walk(path)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    @Test
    public void createTransferAndScanViaApi() throws Exception {
        mockMvc.perform(post("/api/keys/rotate")
                        .param("payeeId", "alice"))
                .andExpect(status().isOk());

        CreateTransferRequest request = new CreateTransferRequest();
        request.setRequestId("api-req-1");
        request.setFromPayeeId("bob");
        request.setToPayeeId("alice");
        request.setMemos(List.of("hello from api"));

        mockMvc.perform(post("/api/transfers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        MvcResult result = mockMvc.perform(post("/api/scan")
                        .param("payeeId", "alice"))
                .andExpect(status().isOk())
                .andReturn();

        ScanResult scanResult = objectMapper.readValue(
                result.getResponse().getContentAsString(), ScanResult.class);

        System.out.println("DEBUG: recovered=" + scanResult.getRecovered().size());
        scanResult.getRecovered().forEach(m -> System.out.println("DEBUG: memo=" + m.getPlaintext() + " gen=" + m.getKeyGenId() + " seq=" + m.getSeq()));

        assertEquals(1, scanResult.getRecovered().size());
    }
}
