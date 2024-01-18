package com.aungmyooo.auth.controller;

import com.aungmyooo.auth.token.Token;
import com.aungmyooo.auth.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public class LogoutService implements LogoutHandler {

    private TokenRepository repository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if(authHeader == null ||!authHeader.startsWith("Bearer")){
            return;
        }
        jwt = authHeader.substring(7);
        Token storedToken = repository.findByToken(jwt).orElse(null);
        if(storedToken != null){
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            repository.save(storedToken);
        }
    }
}
