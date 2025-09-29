package com.soccercommunity.api.user.service;

import com.soccercommunity.api.user.domain.UserEntity;
import com.soccercommunity.api.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUserEmail(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> " + "해당 유저를 찾을 수 없습니다."));
    }

    private UserDetails createUserDetails(UserEntity userEntity) {
        // 여기서 권한을 설정할 수 있습니다. 예: userEntity.getRole().toString()
        return new User(
                String.valueOf(userEntity.getUserId()),
                userEntity.getUserPassword(),
                Collections.singletonList(() -> "ROLE_USER")
        );
    }
}
