package com.soccercommunity.api.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class NaverUserProfileDto {
    private String resultcode;
    private String message;
    private Response response;

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Response {
        private String id;
        private String name;
        private String email;
    }
}
