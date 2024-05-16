package com.oop.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oop.security.dto.CustomUserDetails;
import com.oop.security.entity.RefreshEntity;
import com.oop.security.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final ObjectMapper objectMapper;
    private RefreshRepository refreshRepository;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, ObjectMapper objectMapper, RefreshRepository refreshRepository) {

        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.objectMapper = objectMapper;
        this.refreshRepository = refreshRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

//        String username = obtainUsername(request);
//        String password = obtainPassword(request);
        String username = null;
        String password = null;
        try {
            // JSON 형식의 바디를 파싱하여 사용자 이름과 비밀번호를 추출합니다.
            Map<String, String> requestMap = objectMapper.readValue(request.getInputStream(), Map.class);
            username = requestMap.get("username");
            password = requestMap.get("password");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                username,
                password,
                null
        );

        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 시 실행하는 메서드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authentication
    ) {

        // 유저 정보
        String username = authentication.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // 토큰
        String access = jwtUtil.createJwt("access", username, role, 600000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 8640000L);

        // Refresh 토큰 저장
        addRefreshEntity(username, refresh, 8640000L);

        // 응답  설정
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }

    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    // 로그인 실패 시 실행하는 메서드
    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException failed) {

        response.setStatus(401);
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24 * 60 * 60);
//        cookie.setSecure(true);
//        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
