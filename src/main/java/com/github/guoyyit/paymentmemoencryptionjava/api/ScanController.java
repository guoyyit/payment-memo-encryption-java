package com.github.guoyyit.paymentmemoencryptionjava.api;

import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import com.github.guoyyit.paymentmemoencryptionjava.service.MemoService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Scan API placeholder.
 */
@RestController
@RequestMapping("/api/scan")
public class ScanController {

    private final MemoService service;

    public ScanController(MemoService service) {
        this.service = service;
    }

    @PostMapping
    public ScanResult scan(@RequestParam String payeeId) {
        return service.scan(payeeId);
    }
}
