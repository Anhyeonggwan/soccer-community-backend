package com.soccercommunity.api.user.naver;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.soccercommunity.api.user.dto.NaverTokenResponseDto;
import com.soccercommunity.api.user.dto.NaverUserProfileDto;
import com.soccercommunity.api.common.exception.CustomException;
import com.soccercommunity.api.common.response.ErrorCode;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class NaverApi {

    private final RestTemplate restTemplate;

    @Value("${naver.client.id}")
    private String naverClientId;

    @Value("${naver.client.secret}")
    private String naverClientSecret;

    @Value("${naver.token.uri}")
    private String naverTokenUri;

    @Value("${naver.userinfo.uri}")
    private String naverUserInfoUri;

    /* 네이버 Access Token 발급 */
    public String getAccessToken(String code, String state){
        // HttpHeader Object
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        // HttpBody Object
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", naverClientId);
        params.add("client_secret", naverClientSecret);
        params.add("code", code);
        params.add("state", state);

        HttpEntity<MultiValueMap<String, String>> naverTokenRequest = new HttpEntity<>(params, headers);
        
        try {
            NaverTokenResponseDto responseDto = restTemplate.postForObject(naverTokenUri, naverTokenRequest, NaverTokenResponseDto.class);
            String accessToken = Objects.requireNonNull(responseDto).getAccessToken();
            if (accessToken == null) {
                throw new CustomException(ErrorCode.NAVER_TOKEN_REQUEST_FAILED);
            }
            return accessToken;
        } catch (RestClientException e) {
            log.error("Naver API token request failed: {}", e.getMessage());
            // TODO: handle exception
            throw new IllegalStateException("네이버 API 요청에 실패했습니다.", e);
        }
        
    }

    /* 네이버 사용자 프로필 조회 */
    public NaverUserProfileDto.Response getUserInfo(String accessToken) {
        // 1. HTTP Header 생성
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        try {
            // 2. GET 방식으로 API 요청
            ResponseEntity<NaverUserProfileDto> responseEntity = restTemplate.exchange(
                    naverUserInfoUri,
                    HttpMethod.GET,
                    requestEntity,
                    NaverUserProfileDto.class // 전체 응답을 담는 외부 DTO로 받음
            );

            NaverUserProfileDto profileDto = responseEntity.getBody();

            // 3. 응답 결과 코드 확인 및 예외 처리
            if (profileDto == null || !"00".equals(profileDto.getResultcode())) {
                String message = profileDto != null ? profileDto.getMessage() : "Response body is null";
                log.error("Naver user info API call failed: {}", message);
                throw new IllegalStateException("네이버 사용자 정보를 가져오는데 실패했습니다: " + message);
            }

            log.debug("Successfully fetched Naver user info for user id: {}", profileDto.getResponse().getId());
            
            // 4. 실제 프로필 정보가 담긴 내부 Response 객체 반환
            return profileDto.getResponse();

        } catch (RestClientException e) {
            log.error("Naver API user info request failed: {}", e.getMessage());
            throw new IllegalStateException("네이버 API 요청에 실패했습니다.", e);
        }
    }

}
