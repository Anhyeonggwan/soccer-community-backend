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
import com.soccercommunity.api.user.dto.*;
import com.soccercommunity.api.user.dto.NaverUserProfileDto.Response;
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
import java.util.UUID;
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
    private final RedisTemplate<String, Object> redisTemplate;
    private final NaverApi naverApi;
    private final CustomUserDetailsService customUserDetailsService;

    @Value("${google.client.id}")
    private String googleClientId;

    private static final String NAVER_PREFIX = "NAVER_";

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

    /* Naver 인증 */
    public String naverAuth(String code, String state) {
        String accessToken = naverApi.getAccessToken(code, state);
        NaverUserProfileDto.Response naverUserInfo = naverApi.getUserInfo(accessToken);

        /* uuid 식별 */
        String uuid = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(
                NAVER_PREFIX + uuid,
                naverUserInfo,
                10, // 10분
                TimeUnit.MINUTES
        );

        return uuid;
    }

    /* Naver 로그인/회원가입 */
    @Transactional
    public LoginResultDto naverLogin(String uuid, String code) {
        if(redisTemplate.opsForValue().get(NAVER_PREFIX + uuid) == null) {
            throw new CustomException(ErrorCode.NAVER_UUID_NOT_FOUND_IN_REDIS);
        }

        NaverUserProfileDto.Response naverUserInfo = (Response) redisTemplate.opsForValue().get(NAVER_PREFIX + uuid);

        LoginResultDto resultDto = processSocialLogin(code, AuthProvider.NAVER, naverUserInfo, naverUserInfo.getId(), naverUserInfo.getEmail(), UserEntity::from);
        redisTemplate.delete(NAVER_PREFIX + uuid);

        return resultDto;
    }

    /* Google 로그인/회원가입 */
    @Transactional
    public LoginResultDto googleLogin(String idToken, String code) {
        GoogleSignUpRequestDto googleUserInfo = googleCheck(idToken);
        return processSocialLogin(code, AuthProvider.GOOGLE, googleUserInfo, googleUserInfo.getId(), googleUserInfo.getEmail(), UserEntity::from);
    }

    /* 소셜 로그인 통합 처리 */
    @Transactional
    private <T> LoginResultDto processSocialLogin(String code, AuthProvider provider, T userInfo, String providerId, String email, Function<T, UserEntity> fromFunction) {
        Optional<UserSocialLogin> socialLoginOpt = userSocialLoginRepository.findByProviderAndProviderId(provider, providerId);

        UserEntity user = null;
        if (socialLoginOpt.isPresent()) {

            if(code.equals("login")) {  // 로그인하는 경우
                user = socialLoginOpt.get().getUser();
            }else if(code.equals("signup")) { // 회원가입을 하는 경우
                throw new CustomException(ErrorCode.EMAIL_EXISTS_AS_SOCIAL);
            }
        } else {
            if(code.equals("login")) {  // 로그인하는 경우
                throw new CustomException(ErrorCode.USER_NOT_FOUND);
            } else if(code.equals("signup")) {  // 회원가입을 하는 경우
                userRepository.findByUserEmail(email).ifPresent(existingUser -> {
                    if (existingUser.getSocialLogins() == null || existingUser.getSocialLogins().isEmpty()) {
                        // 일반 계정으로 이미 가입된 경우
                        throw new CustomException(ErrorCode.EMAIL_EXISTS_AS_REGULAR);
                    } else {
                        // 다른 소셜 계정으로 이미 가입된 경우
                        throw new CustomException(ErrorCode.EMAIL_EXISTS_AS_SOCIAL);
                    }
                });

                // 위에서 에러가 발생하지 않았다면, 새로운 사용자이므로 생성 진행
                user = fromFunction.apply(userInfo);
                userRepository.save(user);

                UserSocialLogin socialLogin = UserSocialLogin.builder()
                        .user(user)
                        .provider(provider)
                        .providerId(providerId)
                        .build();
                userSocialLoginRepository.save(socialLogin);
                user.addSocialLogin(socialLogin);
            }
            
        }

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getUserRole()));
        Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUserId(), null, authorities);

        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // Redis에 Refresh Token 저장
        redisTemplate.opsForValue().set(
                String.valueOf(user.getUserId()),
                tokenDto.getRefreshToken(),
                1, // 7일
                TimeUnit.DAYS
        );

        UserInfoDto userInfoDto = UserInfoDto.from(user);
        LoginResponseDto loginResponseDto = LoginResponseDto.builder()
                .accessToken(tokenDto.getAccessToken())
                .userInfo(userInfoDto)
                .build();

        return LoginResultDto.builder()
                .loginResponse(loginResponseDto)
                .refreshToken(tokenDto.getRefreshToken())
                .build();
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
    public LoginResultDto login(String email, String password) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        UserEntity user = userRepository.findByUserEmail(email)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getUserRole()));
        Authentication findAuthentication = new UsernamePasswordAuthenticationToken(user.getUserId(), null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(findAuthentication);

        // Redis에 Refresh Token 저장
        redisTemplate.opsForValue().set(
                String.valueOf(user.getUserId()),
                tokenDto.getRefreshToken(),
                1, // 1일
                TimeUnit.DAYS
        );

        UserInfoDto userInfoDto = UserInfoDto.from(user);
        LoginResponseDto loginResponseDto = LoginResponseDto.builder()
                .accessToken(tokenDto.getAccessToken())
                .userInfo(userInfoDto)
                .build();

        return LoginResultDto.builder()
                .loginResponse(loginResponseDto)
                .refreshToken(tokenDto.getRefreshToken())
                .build();
    }

    /* 토큰 재발급 */
    @Transactional
    public LoginResultDto reissue(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            log.warn("Invalid or expired incoming refreshToken: {}", refreshToken);
            throw new CustomException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        Long userId = Long.parseLong(jwtTokenProvider.getSubject(refreshToken));
        log.info("Extracted userId from refreshToken: {}", userId);

        // Redis에서 저장된 Refresh Token 조회 및 검증
        String storedRefreshToken = redisTemplate.opsForValue().get(String.valueOf(userId)).toString();
        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            throw new CustomException(ErrorCode.REFRESH_TOKEN_MISMATCH);
        }
        
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        UserDetails userDetails = customUserDetailsService.loadUserById(userId);
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // Redis에 새로운 Refresh Token 저장
        redisTemplate.opsForValue().set(
                String.valueOf(userId),
                tokenDto.getRefreshToken(),
                7, // 7일
                TimeUnit.DAYS
        );

        UserInfoDto userInfoDto = UserInfoDto.from(user);
        LoginResponseDto loginResponseDto = LoginResponseDto.builder()
                .accessToken(tokenDto.getAccessToken())
                .userInfo(userInfoDto)
                .build();

        return LoginResultDto.builder()
                .loginResponse(loginResponseDto)
                .refreshToken(tokenDto.getRefreshToken())
                .build();
    }

    /* 로그아웃 */
    @Transactional
    public void logout(String accessToken) {
        if (!jwtTokenProvider.validateToken(accessToken)) {
            throw new CustomException(ErrorCode.INVALID_ACCESS_TOKEN);
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        String userId = authentication.getName();

        // Redis에서 Refresh Token 삭제
        if (redisTemplate.opsForValue().get(userId) != null) {
            redisTemplate.delete(userId);
        }

        // Access Token을 블랙리스트에 추가
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

    /* 나의 정보 가져오기 */
    public LoginResponseDto getMe(String accessToken) {
        if (!jwtTokenProvider.validateToken(accessToken)) {
            throw new CustomException(ErrorCode.INVALID_ACCESS_TOKEN);
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        String userId = authentication.getName();
        UserEntity user = userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        UserInfoDto userInfoDto = UserInfoDto.from(user);

        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);
        redisTemplate.opsForValue().set(
                String.valueOf(user.getUserId()),
                tokenDto.getRefreshToken(),
                1, // 1일
                TimeUnit.DAYS
        );

        return LoginResponseDto.builder()
                .accessToken(tokenDto.getAccessToken())
                .userInfo(userInfoDto)
                .build();
    }

}