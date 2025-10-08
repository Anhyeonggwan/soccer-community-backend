package com.soccercommunity.api.user.domain;

import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;

import com.soccercommunity.api.common.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import com.soccercommunity.api.user.dto.SignUpRequestDto;
import com.soccercommunity.api.user.dto.GoogleSignUpRequestDto;
import com.soccercommunity.api.user.dto.NaverUserProfileDto;

import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.persistence.OneToMany;
import jakarta.persistence.CascadeType;
import java.util.List;
import java.util.ArrayList;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@DynamicUpdate
@Table(name = "users")
@SQLDelete(sql = "UPDATE users SET deleted = true WHERE user_id = ?") // Soft delete implementation
@SQLRestriction("deleted = false")
public class UserEntity extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false, updatable = false)
    private Long userId;

    @Column(name = "user_name", nullable = false, length = 100)
    private String userName;

    @Column(name = "user_email", nullable = false, unique = true, length = 100)
    private String userEmail;

    @Column(name = "user_password", length = 100)
    private String userPassword;

    @Column(name = "nickname", unique = true, length = 100)
    private String nickname;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<UserSocialLogin> socialLogins = new ArrayList<>();

    @Column(name = "user_role")
    @Builder.Default
    private String userRole = "ROLE_USER"; // e.g., ROLE_USER, ROLE_ADMIN

    /* 회원 데이터 생성 */
    public static UserEntity from(SignUpRequestDto requestDto, PasswordEncoder passwordEncoder) {
        return UserEntity.builder()
                .userEmail(requestDto.getEmail())
                .userPassword(passwordEncoder.encode(requestDto.getPassword()))
                .nickname(requestDto.getNickname())
                .userName(requestDto.getName())
                .build();
    }

    public static UserEntity from(NaverUserProfileDto.Response requestDto) {
        return UserEntity.builder()
                .userEmail(requestDto.getEmail())
                .userName(requestDto.getName())
                .build();
    }

    /* 구글 회원 데이터 생성 */
    public static UserEntity from(GoogleSignUpRequestDto requestDto) {
        return UserEntity.builder()
                .userEmail(requestDto.getEmail())
                .userName(requestDto.getName())
                .build();
    }

    // 소셜 로그인 추가 편의 메소드
    public void addSocialLogin(UserSocialLogin socialLogin) {
        this.socialLogins.add(socialLogin);
    }

    // 닉네임 수정 메서드
    public void setUserNickname(String nickname) {
        this.nickname = nickname;
    }
}
