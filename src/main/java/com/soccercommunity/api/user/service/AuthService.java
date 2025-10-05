package com.soccercommunity.api.user.service;

import com.soccercommunity.api.user.repository.UserRepository;
import com.soccercommunity.api.user.repository.UserSocialLoginRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.soccercommunity.api.common.exception.CustomException;
import com.soccercommunity.api.common.response.ErrorCode;
import com.soccercommunity.api.security.jwt.JwtTokenProvider;
import com.soccercommunity.api.user.domain.AuthProvider;
import com.soccercommunity.api.user.domain.UserEntity;
import com.soccercommunity.api.user.domain.UserSocialLogin;
import com.soccercommunity.api.user.dto.GoogleSignUpRequestDto;
import com.soccercommunity.api.user.dto.LinkGoogleRequestDto;
import com.soccercommunity.api.user.dto.ReissueRequestDto;
import com.soccercommunity.api.user.dto.SignUpRequestDto;
import com.soccercommunity.api.user.dto.TokenDto;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final UserSocialLoginRepository userSocialLoginRepository;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${google.client.id}")
    private String googleClientId;

    /* 회원가입 */
    @Transactional
    public void signUp(SignUpRequestDto requestDto) {
        if (userRepository.existsByUserEmail(requestDto.getEmail())) {
            throw new CustomException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }
        UserEntity newUser = UserEntity.from(requestDto, passwordEncoder);
        userRepository.save(newUser);
    }

    /* Google ID 토큰 검증 */
    public GoogleSignUpRequestDto googleCheck(String idToken) {
        // Google API를 호출하여 토큰을 검증하고, 유효한 경우
        // 토큰에서 email, name, id(sub) 등을 추출하여 GoogleSignUpRequestDto에 담아 반환합니다.
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance())
                .setAudience(java.util.Collections.singletonList(googleClientId)) // 여기에 실제 클라이언트 ID를 넣으세요
                .build();

        String subject = null;
        String email = null;
        String name = null;
        
        try {
            GoogleIdToken payload = verifier.verify(idToken);
            GoogleIdToken.Payload pl = payload.getPayload();
            if (pl == null) {  
                throw new CustomException(ErrorCode.INVALID_GOOGLE_TOKEN);
            }
            subject = pl.getSubject();
            email = pl.getEmail();
            name = (String) pl.get("name");
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            throw new CustomException(ErrorCode.INVALID_GOOGLE_TOKEN); // 에러 처리
        }
        
        return GoogleSignUpRequestDto.builder()
            .id(subject)    // 토큰의 'sub' 값
            .email(email)  // 토큰의 'email' 값
            .name(name) // 토큰의 'name' 값
            .build();
    }

    /* Google 로그인/회원가입 */
    @Transactional
    public TokenDto googleLogin(String idToken) {
        // 1. Google ID 토큰 검증 및 사용자 정보 추출
        GoogleSignUpRequestDto googleUserInfo = googleCheck(idToken);
        String providerId = googleUserInfo.getId();
        String email = googleUserInfo.getEmail();

        // 2. UserSocialLogin 테이블에서 해당 providerId로 등록된 소셜 로그인 정보가 있는지 확인
        Optional<UserSocialLogin> socialLoginOpt = userSocialLoginRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, providerId);

        UserEntity user;
        if (socialLoginOpt.isPresent()) {
            // 2-1. 이미 소셜 로그인 정보가 있다면, 기존 사용자
            user = socialLoginOpt.get().getUser();
        } else {
            // 2-2. 소셜 로그인 정보가 없다면, 새로운 소셜 로그인 시도
            // 해당 이메일로 기존 UserEntity가 있는지 확인
            Optional<UserEntity> existingUserOpt = userRepository.findByUserEmail(email);

            if (existingUserOpt.isPresent()) {
                // 2-2-1. 이메일은 같지만, 소셜 로그인이 연결되지 않은 기존 유저인 경우, 계정 연동이 필요하므로 에러를 발생시킨다.
                throw new CustomException(ErrorCode.USER_ALREADY_EXISTS);
            } else {
                // 2-2-2. 완전히 새로운 유저인 경우 (회원가입)
                user = UserEntity.from(googleUserInfo);
                userRepository.save(user);
            }

            // UserSocialLogin 정보 저장 및 UserEntity에 연결
            UserSocialLogin socialLogin = UserSocialLogin.builder()
                    .user(user)
                    .provider(AuthProvider.GOOGLE)
                    .providerId(providerId)
                    .build();
            userSocialLoginRepository.save(socialLogin);
            user.addSocialLogin(socialLogin); // 양방향 관계 관리
        }

        // 3. 인증 객체 생성 (소셜 로그인 사용자는 비밀번호가 없으므로, UserDetails를 직접 생성)
        // CustomUserDetailsService에서 UserDetails를 로드하는 로직이 필요할 수 있음
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getUserRole()));
        Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUserId(), null, authorities);

        // 4. JWT 토큰 생성
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // 5. RefreshToken Redis에 저장
        redisTemplate.opsForValue().set(
                authentication.getName(),
                tokenDto.getRefreshToken(),
                1, // 리프레시 토큰 유효기간 (일)
                TimeUnit.DAYS
        );

        return tokenDto;
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

        // 2-1. 인증된 사용자의 UserEntity를 가져와 userId와 권한으로 새로운 Authentication 객체 생성
        UserEntity user = userRepository.findByUserEmail(email)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));  // 사용자 정보가 없을 경우 예외 처리
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getUserRole()));
        Authentication findAuthentication = new UsernamePasswordAuthenticationToken(user.getUserId(), null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(findAuthentication);

        // 4. RefreshToken Redis에 저장
        redisTemplate.opsForValue().set(
                findAuthentication.getName(),   // principal이 userId이므로 getName()은 userId를 반환
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

    /* 로그아웃 */
    @Transactional
    public void logout(String accessToken) {
        // 1. Access Token 검증
        if (!jwtTokenProvider.validateToken(accessToken)) {
            throw new CustomException(ErrorCode.INVALID_ACCESS_TOKEN);
        }

        // 2. Access Token에서 Authentication 객체 가져오기
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);

        // 3. Redis에서 해당 유저의 Refresh Token 삭제
        if (redisTemplate.opsForValue().get(authentication.getName()) != null) {
            redisTemplate.delete(authentication.getName());
        }

        // 4. Access Token을 블랙리스트에 추가
        Long expiration = jwtTokenProvider.getRemainingMilliseconds(accessToken);
        redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);
    }

    /* Google 계정 연동 */
    @Transactional
    public void linkGoogleAccount(LinkGoogleRequestDto requestDto) {
        // 1. 이메일/비밀번호로 기존 계정 인증
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(requestDto.getEmail(), requestDto.getPassword());
        authenticationManager.authenticate(authenticationToken);

        // 2. 인증된 사용자 정보 가져오기
        UserEntity user = userRepository.findByUserEmail(requestDto.getEmail())
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        // 3. Google ID 토큰 검증 및 정보 추출
        GoogleSignUpRequestDto googleUserInfo = googleCheck(requestDto.getIdToken());

        // 4. 기존 계정의 이메일과 구글 계정의 이메일이 일치하는지 확인
        if (!user.getUserEmail().equals(googleUserInfo.getEmail())) {
            throw new CustomException(ErrorCode.EMAIL_MISMATCH);
        }

        // 5. 이미 해당 구글 계정이 다른 유저에게 연동되어 있는지 확인
        userSocialLoginRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, googleUserInfo.getId())
                .ifPresent(socialLogin -> {
                    throw new CustomException(ErrorCode.USER_ALREADY_EXISTS); // 혹은 다른 적절한 에러 코드
                });

        // 6. 현재 유저가 이미 구글 계정과 연동되어 있는지 확인
        if (userSocialLoginRepository.existsByUserAndProvider(user, AuthProvider.GOOGLE)) {
            throw new CustomException(ErrorCode.USER_ALREADY_EXISTS); // 혹은 다른 적절한 에러 코드
        }

        // 7. UserSocialLogin 정보 저장 및 UserEntity에 연결
        UserSocialLogin socialLogin = UserSocialLogin.builder()
                .user(user)
                .provider(AuthProvider.GOOGLE)
                .providerId(googleUserInfo.getId())
                .build();
        userSocialLoginRepository.save(socialLogin);
        user.addSocialLogin(socialLogin); // 양방향 관계 관리
    }
}