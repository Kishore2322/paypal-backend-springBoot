package com.paypal.user_service.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;

@Component
//@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    public final JwtUtil jwtUtil;

    public JwtRequestFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);
            } catch (Exception e) {
                //log
            }
        }
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //username = null not authenticated
            if (jwtUtil.validateToken(jwt, username)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(username, null, null);
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }


        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            if (jwt == null || jwt.isBlank()) {
                filterChain.doFilter(request, response);
                return; // skip processing if token empty
            }
            try {
                // only extract role if JWT is valid and present
                username = jwtUtil.extractUsername(jwt);
                // use role for authorities as needed
                String role = jwtUtil.extractRole(jwt);
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                List.of(new SimpleGrantedAuthority(role))
                        );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);


                filterChain.doFilter(request, response);
            } catch (Exception e) {
                // log error if you want
            }
        } else {
            filterChain.doFilter(request, response);
//            return;
        }

    }
}
