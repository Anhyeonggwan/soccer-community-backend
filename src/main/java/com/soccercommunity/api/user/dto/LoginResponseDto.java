package com.soccercommunity.api.user.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponseDto {
    private String accessToken;
    private UserInfoDto userInfo;
}
