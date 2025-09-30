package com.soccercommunity.api.email.controller;

import com.soccercommunity.api.common.response.ApiResponse;
import com.soccercommunity.api.common.response.SuccessCode;
import com.soccercommunity.api.email.dto.EmailDto;
import com.soccercommunity.api.email.service.EmailService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/email")
@RequiredArgsConstructor
public class EmailController {

    private final EmailService emailService;

    @PostMapping("/send-verification")
    public ResponseEntity<ApiResponse<Void>> sendVerificationEmail(@Valid @RequestBody EmailDto.VerificationRequest request) {
        emailService.sendVerificationEmail(request.getEmail());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }
}
