package com.soccercommunity.api.user.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequestDto {
    private String name;
    private String email;
    private String password;
    private String nickname;
}
