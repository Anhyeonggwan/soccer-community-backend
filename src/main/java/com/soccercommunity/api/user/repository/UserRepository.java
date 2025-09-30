package com.soccercommunity.api.user.repository;

import com.soccercommunity.api.user.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUserEmail(String email);

    /* 이메일 중복 체크 */
    boolean existsByUserEmail(String email);

    /* 닉네임 중복 체크 */
    boolean existsByNickname(String nickname);
}
