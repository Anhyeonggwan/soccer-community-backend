package com.soccercommunity.api.email.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

public class EmailDto {

    @Getter
    @NoArgsConstructor
    public static class VerificationRequest {
        @NotBlank(message = "이메일은 필수 입력 값입니다.")
        @Email(message = "이메일 형식이 올바르지 않습니다.")
        private String email;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class VerificationCodeRequest {
        @NotBlank(message = "이메일은 필수 입력 값입니다.")
        @Email(message = "이메일 형식이 올바르지 않습니다.")
        private String email;

        @NotBlank(message = "인증 코드는 필수 입력 값입니다.")
        private String code;
    }
}
