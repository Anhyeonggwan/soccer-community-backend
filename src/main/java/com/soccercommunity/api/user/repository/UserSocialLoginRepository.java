package com.soccercommunity.api.user.repository;

import com.soccercommunity.api.user.domain.AuthProvider;
import com.soccercommunity.api.user.domain.UserSocialLogin;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserSocialLoginRepository extends JpaRepository<UserSocialLogin, Long> {
    Optional<UserSocialLogin> findByProviderAndProviderId(AuthProvider provider, String providerId);
    Optional<UserSocialLogin> findByIdAndProvider(Long userId, AuthProvider provider);
}