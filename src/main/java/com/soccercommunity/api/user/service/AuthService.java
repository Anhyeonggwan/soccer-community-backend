package com.soccercommunity.api.user.service;

import com.soccercommunity.api.common.exception.CustomException;
import com.soccercommunity.api.common.response.ErrorCode;
import com.soccercommunity.api.security.jwt.JwtTokenProvider;
import com.soccercommunity.api.user.dto.TokenDto;
import com.soccercommunity.api.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import com.soccercommunity.api.user.domain.UserEntity;
import com.soccercommunity.api.user.dto.SignUpRequestDto;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /* 회원가입 */
    @Transactional
    public void signUp(SignUpRequestDto requestDto) {
        UserEntity newUser = UserEntity.from(requestDto, passwordEncoder);
        userRepository.save(newUser);
    }

    /* 닉네임 중복 체크 체크 */
    public void checkNickName(String nickname) {
        if(userRepository.existsByNickname(nickname)) {
            throw new CustomException(ErrorCode.NICKNAME_ALREADY_EXISTS);
        }
    }

    /* 이메일 중복 체크 */
    public void checkEmail(String email) {
        if (userRepository.existsByUserEmail(email)) {
            throw new CustomException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }
    }

    /* 로그인 */
    @Transactional
    public TokenDto login(String email, String password) {
        // 1. Login ID/PW 를 기반으로 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);

        // 2. 실제로 검증 (사용자 비밀번호 체크) 이 이루어지는 부분
        //    authenticate 메서드가 실행이 될 때 CustomUserDetailsService 에서 만들었던 loadUserByUsername 메서드가 실행됨
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        String token = jwtTokenProvider.createToken(authentication);

        return TokenDto.builder()
                .grantType("Bearer")
                .accessToken(token)
                .build();
    }
}