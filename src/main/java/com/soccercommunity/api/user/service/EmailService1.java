package com.soccercommunity.api.user.service;

// import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

// import jakarta.mail.internet.MimeMessage;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService1 {

    // private final JavaMailSender mailSender;

    @Transactional
    public void sendEmail(String email) {
        // MimeMessage mimeMessage = null;
    }

    /* 이메일 메시지 생성 */
    /*
    private MimeMessage createMessage(String email) {

        MimeMessage mimeMessage = mailSender.createMimeMessage();
        return mimeMessage;
    }
    */

    private String createAuthCode() {
        StringBuilder authCode = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            int randomDigit = (int) (Math.random() * 10);
            authCode.append(randomDigit);
        }
        return authCode.toString();
    }

}
