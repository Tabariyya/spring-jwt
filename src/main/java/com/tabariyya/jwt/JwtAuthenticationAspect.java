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
import org.slf4j.MDC;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.core.MethodParameter;
import org.springframework.core.convert.ConversionException;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;


@Component
@Aspect
@ConditionalOnProperty(name = "JwtAuthenticationAspect.enabled", matchIfMissing = true)
public class JwtAuthenticationAspect {
    private static final TypeDescriptor STRING_TYPE = TypeDescriptor.valueOf(String.class);

    private final JwtConsumer jwtConsumer;
    private final ConversionService conversionService;

    /**
     * @param mvcConversionService the MVC conversion service, which Spring Boot has already populated with every
     *                             {@code Converter}, {@code ConverterFactory} and {@code Formatter} bean the
     *                             application declares — so a consumer teaches this aspect about a custom user id
     *                             type simply by declaring such a bean.
     * @param conversionService    any other single {@code ConversionService} bean, used when there is no MVC one.
     */
    public JwtAuthenticationAspect(JwtConsumer jwtConsumer,
                                   @Qualifier("mvcConversionService") ObjectProvider<ConversionService> mvcConversionService,
                                   ObjectProvider<ConversionService> conversionService) {
        this.jwtConsumer = jwtConsumer;
        this.conversionService = mvcConversionService.getIfAvailable(
                () -> conversionService.getIfUnique(ApplicationConversionService::getSharedInstance));
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

        boolean mdcSet = false;
        request.setAttribute("jwtPayload", jwtPayload);

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Object[] args = joinPoint.getArgs();
        Parameter[] parameters = method.getParameters();
        JsonElement userIdClaim = jwtPayload.get(Claims.SUBJECT);
        if (userIdClaim != null && userIdClaim.isJsonPrimitive()) {
            String rawUserId = userIdClaim.getAsString();
            MDC.put("userId", rawUserId);
            mdcSet=true;
            for (int i = 0; i < parameters.length; i++) {
                if (parameters[i].getName().equals("userId")) {
                    args[i] = convertUserId(rawUserId, new MethodParameter(method, i));
                    break;
                }
            }
        }

        try {
            return joinPoint.proceed(args);
        } finally {
            if (mdcSet) {
                MDC.remove("userId");
            }
        }
    }

    private Object convertUserId(String raw, MethodParameter parameter) {
        TypeDescriptor targetType = new TypeDescriptor(parameter);
        if (!conversionService.canConvert(STRING_TYPE, targetType)) {
            throw new IllegalStateException("Cannot convert the JWT subject to the 'userId' parameter type "
                    + targetType.getType().getName() + " of " + parameter.getExecutable()
                    + ". Declare a Converter<String, " + targetType.getType().getSimpleName() + "> bean.");
        }
        try {
            return conversionService.convert(raw, STRING_TYPE, targetType);
        } catch (ConversionException ex) {
            // The token carries a subject that is not a valid id of the expected type.
            throw new UnauthorizedException();
        }
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
