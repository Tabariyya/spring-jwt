package com.tabariyya.jwt;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;

@Component
@ConditionalOnProperty(name = "cors.allowed-origins", matchIfMissing = false)
public class CustomCorsFilter implements Filter {

    private final String ALLOWED_ORIGINS;

    public CustomCorsFilter(@Value("${cors.allowed-origins}") String allowedOrigins) {
        ALLOWED_ORIGINS = allowedOrigins;
    }

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String origin = req.getHeader("Origin");

        boolean isAllowed = origin != null && Arrays.stream(ALLOWED_ORIGINS.split(","))
                .map(String::trim)
                .anyMatch(o -> o.equals(origin)) || ALLOWED_ORIGINS.equals("*");
        if (isAllowed) {
            res.setHeader("Access-Control-Allow-Origin", origin);
            res.setHeader("Access-Control-Allow-Credentials", "true");
            res.setHeader("Vary", "Origin");
        }

        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
            res.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        chain.doFilter(request, response);
    }
}
