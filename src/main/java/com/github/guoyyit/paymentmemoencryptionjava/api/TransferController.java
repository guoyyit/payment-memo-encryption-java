package com.github.guoyyit.paymentmemoencryptionjava.api;

import com.github.guoyyit.paymentmemoencryptionjava.dto.CreateTransferRequest;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Transfer;
import com.github.guoyyit.paymentmemoencryptionjava.service.MemoService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Transfer API placeholder.
 */
@RestController
@RequestMapping("/api/transfers")
public class TransferController {

    private final MemoService service;

    public TransferController(MemoService service) {
        this.service = service;
    }

    @PostMapping
    public Transfer create(@RequestBody CreateTransferRequest request) {
        return service.createTransfer(request);
    }
}
