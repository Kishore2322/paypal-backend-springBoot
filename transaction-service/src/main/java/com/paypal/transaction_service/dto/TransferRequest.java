package com.paypal.transaction_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TransferRequest {

    private String senderName;
    private String receiverName;
    private Double amount;

}
