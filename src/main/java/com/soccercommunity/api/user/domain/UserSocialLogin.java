package com.soccercommunity.api.user.domain;

import com.soccercommunity.api.common.domain.BaseEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Table(name = "user_social_logins")
@SQLDelete(sql = "UPDATE user_social_logins SET deleted = true WHERE id = ?")
@SQLRestriction("deleted = false")
public class UserSocialLogin extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false)
    private AuthProvider provider;

    @Column(name = "provider_id", nullable = false, unique = true)
    private String providerId;

    // Optional: You might want to store social provider's access/refresh tokens here
    // @Column(name = "social_access_token")
    // private String socialAccessToken;
    // @Column(name = "social_refresh_token")
    // private String socialRefreshToken;
}
