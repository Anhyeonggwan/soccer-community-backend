package com.soccercommunity.api.email.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class EmailService {

    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final int CODE_LENGTH = 6;
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * 영문 + 숫자로 구성된 6자리 인증 코드를 생성합니다.
     */
    public String createAuthCode() {
        StringBuilder code = new StringBuilder(CODE_LENGTH);
        for (int i = 0; i < CODE_LENGTH; i++) {
            int randomIndex = RANDOM.nextInt(CHARACTERS.length());
            code.append(CHARACTERS.charAt(randomIndex));
        }
        return code.toString();
    }

    public void sendVerificationEmail(String email) {
        String authCode = createAuthCode();
        // TODO: 이메일 발송 로직 구현 (JavaMailSender 사용)
        // TODO: 생성된 인증코드를 Redis에 저장 (유효 시간 설정)
        System.out.println("Generated Auth Code for " + email + ": " + authCode);
    }
}
