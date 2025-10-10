package com.soccercommunity.api.user.service;

import com.soccercommunity.api.user.repository.UserRepository;
import com.soccercommunity.api.user.repository.UserSocialLoginRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

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
import com.soccercommunity.api.user.dto.LinkNaverRequestDto;
import com.soccercommunity.api.user.dto.NaverUserProfileDto;
import com.soccercommunity.api.user.dto.SignUpRequestDto;
import com.soccercommunity.api.user.dto.TokenDto;
import com.soccercommunity.api.user.naver.NaverApi;

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
import java.util.function.Function;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final UserSocialLoginRepository userSocialLoginRepository;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, String> redisTemplate;
    private final NaverApi naverApi;
    private final CustomUserDetailsService customUserDetailsService;

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
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance())
                .setAudience(java.util.Collections.singletonList(googleClientId))
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
            throw new CustomException(ErrorCode.INVALID_GOOGLE_TOKEN);
        }
        
        return GoogleSignUpRequestDto.builder()
            .id(subject)
            .email(email)
            .name(name)
            .build();
    }

    /* Naver 로그인/회원가입 */
    @Transactional
    public TokenDto naverLogin(String code, String state) {
        String accessToken = naverApi.getAccessToken(code, state);
        NaverUserProfileDto.Response naverUserInfo = naverApi.getUserInfo(accessToken);
        return processSocialLogin(AuthProvider.NAVER, naverUserInfo, naverUserInfo.getId(), naverUserInfo.getEmail(), UserEntity::from);
    }

    /* Google 로그인/회원가입 */
    @Transactional
    public TokenDto googleLogin(String idToken) {
        GoogleSignUpRequestDto googleUserInfo = googleCheck(idToken);
        return processSocialLogin(AuthProvider.GOOGLE, googleUserInfo, googleUserInfo.getId(), googleUserInfo.getEmail(), UserEntity::from);
    }

    /* 소셜 로그인 통합 처리 */
    @Transactional
    private <T> TokenDto processSocialLogin(AuthProvider provider, T userInfo, String providerId, String email, Function<T, UserEntity> fromFunction) {
        Optional<UserSocialLogin> socialLoginOpt = userSocialLoginRepository.findByProviderAndProviderId(provider, providerId);

        UserEntity user;
        if (socialLoginOpt.isPresent()) {
            user = socialLoginOpt.get().getUser();
        } else {
            Optional<UserEntity> existingUserOpt = userRepository.findByUserEmail(email);

            if (existingUserOpt.isPresent()) {
                throw new CustomException(ErrorCode.USER_ALREADY_EXISTS);
            } else {
                user = fromFunction.apply(userInfo);
                userRepository.save(user);
            }

            UserSocialLogin socialLogin = UserSocialLogin.builder()
                    .user(user)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userSocialLoginRepository.save(socialLogin);
            user.addSocialLogin(socialLogin);
        }

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getUserRole()));
        Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUserId(), null, authorities);

        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        redisTemplate.opsForValue().set(
                authentication.getName(),
                tokenDto.getRefreshToken(),
                1,
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
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        UserEntity user = userRepository.findByUserEmail(email)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getUserRole()));
        Authentication findAuthentication = new UsernamePasswordAuthenticationToken(user.getUserId(), null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(findAuthentication);

        redisTemplate.opsForValue().set(
                findAuthentication.getName(),
                tokenDto.getRefreshToken(),
                1,
                TimeUnit.DAYS
        );
        return tokenDto;
    }

    /* 토큰 재발급 */
    @Transactional
    public TokenDto reissue(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            log.warn("Invalid or expired incoming refreshToken: {}", refreshToken);
            throw new CustomException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        // Refresh Token에서 사용자 ID(subject) 추출
        Long userId = Long.parseLong(jwtTokenProvider.getSubject(refreshToken));
        log.info("Extracted userId from refreshToken: {}", userId);
        UserDetails userDetails = customUserDetailsService.loadUserById(userId);
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        String storedRefreshToken = redisTemplate.opsForValue().get(String.valueOf(userId));
        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            log.warn("RefreshToken mismatch for user {}. Stored: {}, Incoming: {}", userId, storedRefreshToken, refreshToken);
            throw new CustomException(ErrorCode.REFRESH_TOKEN_MISMATCH);
        }

        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        redisTemplate.opsForValue().set(
                String.valueOf(userId),
                tokenDto.getRefreshToken(),
                1,
                TimeUnit.DAYS
        );

        return tokenDto;
    }

    /* 로그아웃 */
    @Transactional
    public void logout(String accessToken) {
        if (!jwtTokenProvider.validateToken(accessToken)) {
            throw new CustomException(ErrorCode.INVALID_ACCESS_TOKEN);
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);

        if (redisTemplate.opsForValue().get(authentication.getName()) != null) {
            redisTemplate.delete(authentication.getName());
        }

        Long expiration = jwtTokenProvider.getRemainingMilliseconds(accessToken);
        redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);
    }

    /* Naver 계정 연동 */
    @Transactional
    public void linkNaverAccount(LinkNaverRequestDto requestDto) {
        // 1. 현재 인증된 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(authentication.getName());
        UserEntity user = userRepository.findById(currentUserId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        // 2. 전달받은 Naver AccessToken으로 사용자 정보 조회
        NaverUserProfileDto.Response naverUserInfo = naverApi.getUserInfo(requestDto.getAccessToken());
        String providerId = naverUserInfo.getId();

        // 3. 해당 네이버 계정이 이미 다른 유저에게 연동되어 있는지 확인
        userSocialLoginRepository.findByProviderAndProviderId(AuthProvider.NAVER, providerId)
                .ifPresent(socialLogin -> {
                    throw new CustomException(ErrorCode.USER_ALREADY_EXISTS);
                });

        // 4. 현재 유저가 이미 네이버 계정과 연동되어 있는지 확인
        if (userSocialLoginRepository.existsByUserAndProvider(user, AuthProvider.NAVER)) {
            throw new CustomException(ErrorCode.USER_ALREADY_EXISTS);
        }

        // 5. UserSocialLogin 정보 저장 및 UserEntity에 연결
        UserSocialLogin socialLogin = UserSocialLogin.builder()
                .user(user)
                .provider(AuthProvider.NAVER)
                .providerId(providerId)
                .build();
        userSocialLoginRepository.save(socialLogin);
        user.addSocialLogin(socialLogin);
    }

    /* Google 계정 연동 */
    @Transactional
    public void linkGoogleAccount(LinkGoogleRequestDto requestDto) {
        // 1. 현재 인증된 사용자 정보 가져오기 (JWT 기반)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = Long.parseLong(authentication.getName());
        UserEntity user = userRepository.findById(currentUserId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        // 2. Google ID 토큰 검증 및 정보 추출
        GoogleSignUpRequestDto googleUserInfo = googleCheck(requestDto.getIdToken());

        // 3. 기존 계정의 이메일과 구글 계정의 이메일이 일치하는지 확인 (선택적이지만, 사용자 혼란 방지를 위해 추천)
        if (!user.getUserEmail().equals(googleUserInfo.getEmail())) {
            throw new CustomException(ErrorCode.EMAIL_MISMATCH);
        }

        // 4. 해당 구글 계정이 이미 다른 유저에게 연동되어 있는지 확인
        userSocialLoginRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, googleUserInfo.getId())
                .ifPresent(socialLogin -> {
                    throw new CustomException(ErrorCode.USER_ALREADY_EXISTS);
                });

        // 5. 현재 유저가 이미 구글 계정과 연동되어 있는지 확인
        if (userSocialLoginRepository.existsByUserAndProvider(user, AuthProvider.GOOGLE)) {
            throw new CustomException(ErrorCode.USER_ALREADY_EXISTS);
        }

        // 6. UserSocialLogin 정보 저장 및 UserEntity에 연결
        UserSocialLogin socialLogin = UserSocialLogin.builder()
                .user(user)
                .provider(AuthProvider.GOOGLE)
                .providerId(googleUserInfo.getId())
                .build();
        userSocialLoginRepository.save(socialLogin);
        user.addSocialLogin(socialLogin);
    }
}