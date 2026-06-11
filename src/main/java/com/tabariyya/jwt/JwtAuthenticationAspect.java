package com.tabariyya.jwt;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.tabariyya.utils.jwt.JwtConsumer;
import com.tabariyya.utils.jwt.TokenType;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.UUID;


@Component
@Aspect
@ConditionalOnProperty(name = "JwtAuthenticationAspect.enabled", matchIfMissing = true)
public class JwtAuthenticationAspect {
    private final JwtConsumer jwtConsumer;

    public JwtAuthenticationAspect(JwtConsumer jwtConsumer) {
        this.jwtConsumer = jwtConsumer;
    }

    @Around("@within(com.tabariyya.jwt.JwtAuthenticated) || @annotation(com.tabariyya.jwt.JwtAuthenticated)")
    public Object checkJwtAuthentication(ProceedingJoinPoint joinPoint) throws Throwable {
        JwtAuthenticated jwtAuthenticated = getJwtAuthenticatedAnnotation(joinPoint);
        if (jwtAuthenticated == null) {
            throw new UnauthorizedException();
        }

        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            throw new UnauthorizedException();
        }

        HttpServletRequest request = attributes.getRequest();
        String authorizationHeader = request.getHeader("Authorization");
        String token = extractJwtFromAuthorizationHeader(authorizationHeader);
        if (token == null) {
            throw new UnauthorizedException();
        }

        JsonObject jwtPayload = jwtConsumer.extractClaims(token).payload();

        TokenType tokenType = TokenType.valueOf(jwtPayload.get("type").getAsString());
        if (!jwtConsumer.verifyToken(token, tokenType)) {
            throw new UnauthorizedException();
        }

        for (Claim claim : jwtAuthenticated.value()) {
            JsonElement element = jwtPayload.get(claim.key());
            if (element == null || !element.getAsString().equals(claim.value())) {
                throw new UnauthorizedException();
            }
        }

        Claim[] anyOfClaims = jwtAuthenticated.anyOf();
        if (anyOfClaims.length > 0) {
            boolean anyMatched = false;
            for (Claim claim : anyOfClaims) {
                JsonElement element = jwtPayload.get(claim.key());
                if (element != null && element.getAsString().equals(claim.value())) {
                    anyMatched = true;
                    break;
                }
            }
            if (!anyMatched) {
                throw new UnauthorizedException();
            }
        }

        request.setAttribute("jwtPayload", jwtPayload);

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Object[] args = joinPoint.getArgs();
        Parameter[] parameters = method.getParameters();
        JsonElement userIdClaim = jwtPayload.get(Claims.SUBJECT);
        if (userIdClaim != null && userIdClaim.isJsonPrimitive()) {
            String rawUserId = userIdClaim.getAsString();
            for (int i = 0; i < parameters.length; i++) {
                if (parameters[i].getName().equals("userId")) {
                    args[i] = convertUserId(rawUserId, parameters[i].getType());
                    break;
                }
            }
        }

        return joinPoint.proceed(args);
    }

    private Object convertUserId(String raw, Class<?> type) {
        if (type == String.class) return raw;
        if (type == Integer.class || type == int.class) return Integer.parseInt(raw);
        if (type == Long.class || type == long.class) return Long.parseLong(raw);
        if (type == UUID.class) return UUID.fromString(raw);
        throw new UnauthorizedException();
    }

    private String extractJwtFromAuthorizationHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return null;
        }
        return authorizationHeader.substring(7);
    }

    private JwtAuthenticated getJwtAuthenticatedAnnotation(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        if (method.isAnnotationPresent(JwtAuthenticated.class)) {
            return method.getAnnotation(JwtAuthenticated.class);
        }

        Class<?> declaringClass = method.getDeclaringClass();
        if (declaringClass.isAnnotationPresent(JwtAuthenticated.class)) {
            return declaringClass.getAnnotation(JwtAuthenticated.class);
        }

        return null;
    }
}
