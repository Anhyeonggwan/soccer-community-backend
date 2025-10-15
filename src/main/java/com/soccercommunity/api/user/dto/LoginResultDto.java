package com.soccercommunity.api.user.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResultDto {
    private LoginResponseDto loginResponse;
    private String refreshToken;
}
