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

    @Column(name = "user_password", nullable = false, length = 100)
    private String userPassword;

    @Column(name = "nickname", unique = true, length = 100)
    private String nickname;

    @Column(name = "user_role")
    @Builder.Default
    private String userRole = "ROLE_USER"; // e.g., ROLE_USER, ROLE_ADMIN

}
