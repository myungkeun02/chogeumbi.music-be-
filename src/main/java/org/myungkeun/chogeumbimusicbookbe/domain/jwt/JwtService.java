package org.myungkeun.chogeumbimusicbookbe.domain.jwt;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.function.Function;

public interface JwtService {
    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver);
    public String extractUsername(String token);
    public String generateAccessToken(UserDetails userDetails);
    public String generateRefreshToken(UserDetails userDetails);
    public boolean isTokenValid(String token, UserDetails userDetails);
    public boolean isTokenExpired(String token);
}
