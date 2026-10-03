package com.github.guoyyit.paymentmemoencryptionjava.api;

import com.github.guoyyit.paymentmemoencryptionjava.keystore.KeyGeneration;
import com.github.guoyyit.paymentmemoencryptionjava.service.MemoService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Key management API placeholder.
 */
@RestController
@RequestMapping("/api/keys")
public class KeyController {

    private final MemoService service;

    public KeyController(MemoService service) {
        this.service = service;
    }

    @PostMapping("/rotate")
    public KeyGeneration rotate(@RequestParam String payeeId) {
        return service.rotateKey(payeeId);
    }

    @PostMapping("/export")
    public Map<String, String> export(@RequestParam String payeeId, @RequestParam String password) {
        return Map.of("bundle", service.exportKeys(payeeId, password.toCharArray()));
    }

    @PostMapping("/import")
    public void importKeys(@RequestParam String payeeId, @RequestParam String password,
                           @RequestParam String bundle) {
        service.importKeys(payeeId, bundle, password.toCharArray());
    }
}
