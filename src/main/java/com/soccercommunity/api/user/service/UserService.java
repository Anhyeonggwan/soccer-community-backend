package com.soccercommunity.api.user.service;

import org.springframework.stereotype.Service;

import com.soccercommunity.api.user.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    /* 닉네임 수정 */
    @Transactional
    public void modifyNickname(String email, String nickname) {
        userRepository.findByUserEmail(email).ifPresent(user -> {
            user.setUserNickname(nickname);
        });
    }   

}
