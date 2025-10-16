package com.soccercommunity.api.user.dto;

import com.soccercommunity.api.user.domain.UserEntity;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserInfoDto {
    private Long id;
    private String name;
    private String email;
    private String nickname;

    public static UserInfoDto from(UserEntity user) {
        return UserInfoDto.builder()
                .id(user.getUserId())
                .name(user.getUserName())
                .email(user.getUserEmail())
                .nickname(user.getNickname())
                .build();
    }
}
