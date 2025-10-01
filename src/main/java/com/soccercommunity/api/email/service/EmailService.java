package com.soccercommunity.api.email.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.time.Duration;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final StringRedisTemplate redisTemplate;
    private final JavaMailSender mailSender;

    private static final String VERIFICATION_CODE_PREFIX = "verification:";
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final int CODE_LENGTH = 6;
    private static final Duration CODE_EXPIRATION = Duration.ofMinutes(3);
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

    /* 이메일 전송 */
    public void sendVerificationEmail(String email) {
        String authCode = createAuthCode();

        try {
            MimeMessage message = createMessage(email, authCode);
            mailSender.send(message);
        } catch (MessagingException | UnsupportedEncodingException e) {
            // 예외 처리 로직 (예: 로깅)
            e.printStackTrace();
            throw new RuntimeException("이메일 전송에 실패했습니다.", e);
        }

        // Redis에 인증 코드 저장 (유효 시간 3분)
        String key = VERIFICATION_CODE_PREFIX + email;
        redisTemplate.opsForValue().set(key, authCode, CODE_EXPIRATION);

        // TODO: 이메일 발송 로직 구현 (JavaMailSender 사용)
        System.out.println("Generated Auth Code for " + email + ": " + authCode);
        System.out.println("Saved to Redis with key: " + key + " and 3-minute expiration.");
    }

    /* 이메일 만들기  */
    private MimeMessage createMessage(String email, String authCode) throws MessagingException, UnsupportedEncodingException {
        MimeMessage mimeMessage = mailSender.createMimeMessage();

        mimeMessage.setFrom(new InternetAddress("anhyeonggwan4@gmail.com", "축구통"));
        mimeMessage.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(email));
        mimeMessage.setSubject("축구통 회원가입 인증 코드");

        String msgOfEmail = "";
        msgOfEmail += "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #f9f9f9;'>";
        msgOfEmail += "<h2 style='color: #333333; text-align: center; margin-bottom: 20px;'>축구통 이메일 인증</h2>";
        msgOfEmail += "<p style='color: #555555; line-height: 1.6;'>안녕하세요!</p>";
        msgOfEmail += "<p style='color: #555555; line-height: 1.6;'>회원가입을 완료하시려면 아래 인증 코드를 입력해주세요.</p>";
        msgOfEmail += "<div style='text-align: center; margin: 30px 0; padding: 20px; background-color: #ffffff; border: 1px dashed #cccccc; border-radius: 5px;'>";
        msgOfEmail += "<p style='font-size: 18px; color: #333333; margin-bottom: 10px;'>인증 코드:</p>";
        msgOfEmail += "<strong style='font-size: 32px; color: #007bff; letter-spacing: 5px;'>" + authCode + "</strong>";
        msgOfEmail += "</div>";
        msgOfEmail += "<p style='color: #555555; line-height: 1.6;'>이 코드는 3분 동안 유효합니다. 만약 본인이 요청하지 않았다면 이 이메일을 무시해주세요.</p>";
        msgOfEmail += "<p style='color: #555555; line-height: 1.6;'>감사합니다.<br>축구통 팀 드림</p>";
        msgOfEmail += "<div style='text-align: center; margin-top: 30px; font-size: 12px; color: #aaaaaa;'>";
        msgOfEmail += "<p>&copy; 2025 축구통. All rights reserved.</p>";
        msgOfEmail += "</div>";
        msgOfEmail += "</div>";
        mimeMessage.setText(msgOfEmail, "utf-8", "html");

        return mimeMessage;
    }

    /**
     * 이메일과 인증 코드를 받아 Redis에 저장된 코드와 비교하여 인증합니다.
     *
     * @param email 인증할 이메일 주소
     * @param code 사용자가 입력한 인증 코드
     * @return 인증 성공 여부 (true: 성공, false: 실패)
     */
    public boolean verifyEmailCode(String email, String code) {
        String key = VERIFICATION_CODE_PREFIX + email;
        String storedCode = redisTemplate.opsForValue().get(key);

        if (storedCode != null && storedCode.equals(code)) {
            redisTemplate.delete(key); // 인증 성공 시 Redis에서 코드 삭제
            return true;
        }
        return false;
    }
}