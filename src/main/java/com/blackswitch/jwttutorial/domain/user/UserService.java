package com.blackswitch.jwttutorial.domain.user;

import com.blackswitch.jwttutorial.domain.auth.Authority;
import com.blackswitch.jwttutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            // FIXME
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

//        return UserDto.from(userRepository.save(user));
        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public User getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username).orElse(null);
    }

    @Transactional(readOnly = true)
    public User getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername()
                        .flatMap(userRepository::findOneWithAuthoritiesByUsername)
                        .orElseThrow(() -> new RuntimeException("Member not found"));
    }
}
