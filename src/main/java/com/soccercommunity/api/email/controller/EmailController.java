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
import com.soccercommunity.api.common.response.ErrorCode;
import com.soccercommunity.api.common.exception.CustomException;

@RestController
@RequestMapping("/api/email")
@RequiredArgsConstructor
public class EmailController {

    private final EmailService emailService;

    /* 이메일 인증 전송 */
    @PostMapping("/send-verification")
    public ResponseEntity<ApiResponse<Void>> sendVerificationEmail(@Valid @RequestBody EmailDto.VerificationRequest request) {
        emailService.sendVerificationEmail(request.getEmail());
        return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
    }

    /* 이메일 인증 코드 확인 */
    @PostMapping("/verify-code")
    public ResponseEntity<ApiResponse<Void>> verifyEmailCode(@Valid @RequestBody EmailDto.VerificationCodeRequest request) {
        boolean isVerified = emailService.verifyEmailCode(request.getEmail(), request.getCode());
        if (isVerified) {
            return ResponseEntity.ok(ApiResponse.success(SuccessCode.OK));
        } else {
            throw new CustomException(ErrorCode.INVALID_VERIFICATION_CODE);
        }
    }
}
