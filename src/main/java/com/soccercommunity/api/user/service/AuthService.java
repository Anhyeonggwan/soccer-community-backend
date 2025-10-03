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
import com.soccercommunity.api.user.dto.ReissueRequestDto;
import com.soccercommunity.api.user.dto.SignUpRequestDto;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.data.redis.core.RedisTemplate;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, String> redisTemplate;

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
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // 4. RefreshToken Redis에 저장
        redisTemplate.opsForValue().set(
                authentication.getName(),
                tokenDto.getRefreshToken(),
                1, // 리프레시 토큰 유효기간 (일)
                TimeUnit.DAYS
        );

        return tokenDto;
    }

    @Transactional
    public TokenDto reissue(ReissueRequestDto tokenRequestDto) {
        // 1. Refresh Token 검증
        if (!jwtTokenProvider.validateToken(tokenRequestDto.getRefreshToken())) {
            throw new CustomException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        // 2. Access Token 에서 Member ID 가져오기
        Authentication authentication = jwtTokenProvider.getAuthentication(tokenRequestDto.getAccessToken());

        // 3. Redis 에서 Member ID 를 기반으로 저장된 Refresh Token 값을 가져옵니다.
        String refreshToken = redisTemplate.opsForValue().get(authentication.getName());
        if (refreshToken == null || !refreshToken.equals(tokenRequestDto.getRefreshToken())) {
            throw new CustomException(ErrorCode.REFRESH_TOKEN_MISMATCH);
        }

        // 4. 새로운 토큰 생성
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // 5. RefreshToken Redis 업데이트
        redisTemplate.opsForValue().set(
                authentication.getName(),
                tokenDto.getRefreshToken(),
                1, // 리프레시 토큰 유효기간 (일)
                TimeUnit.DAYS
        );

        // 토큰 발급
        return tokenDto;
    }
}