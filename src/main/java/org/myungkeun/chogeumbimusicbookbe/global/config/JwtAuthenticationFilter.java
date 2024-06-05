package org.myungkeun.chogeumbimusicbookbe.global.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor

public class JwtAuthenticationFilter {
    private UserDetailsService userDetailsService;
}
