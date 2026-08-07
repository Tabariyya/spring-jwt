package com.tabariyya.jwt;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;

/**
 * Resolves the {@code userId} parameter of {@link JwtAuthenticated} handler methods, so that Spring MVC does not
 * treat it as a model attribute and {@link JwtAuthenticationAspect} can substitute the id carried by the verified
 * token.
 *
 * <p>Spring MVC resolves an unannotated parameter by type: a simple value type such as {@code UUID} falls through
 * to the catch-all request-param resolver, which is not required and so yields {@code null} when absent, while any
 * other type — a strongly typed id, for instance — is taken for a model attribute and constructed from the request
 * parameters, which fails before the handler, and before the aspect, ever runs. This resolver claims the parameter
 * first and gives every type the treatment {@code UUID} used to get.
 */
@Configuration
public class JwtUserIdWebConfig implements WebMvcConfigurer {

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new JwtUserIdArgumentResolver());
    }

    static final class JwtUserIdArgumentResolver implements HandlerMethodArgumentResolver {

        private static final String USER_ID = "userId";

        /** A parameter the caller has bound explicitly is theirs, whatever it happens to be called. */
        private static final List<Class<? extends Annotation>> BINDING_ANNOTATIONS = List.of(
                RequestParam.class, PathVariable.class, RequestBody.class, ModelAttribute.class,
                RequestHeader.class, RequestPart.class, RequestAttribute.class, CookieValue.class,
                SessionAttribute.class, MatrixVariable.class);

        @Override
        public boolean supportsParameter(MethodParameter parameter) {
            if (!USER_ID.equals(parameter.getParameterName())) {
                return false;
            }
            for (Class<? extends Annotation> annotation : BINDING_ANNOTATIONS) {
                if (parameter.hasParameterAnnotation(annotation)) {
                    return false;
                }
            }
            return isJwtAuthenticated(parameter);
        }

        /**
         * Falls back to a {@code userId} request parameter, converted through the application's own
         * {@code ConversionService}. Whenever the aspect is enabled it overwrites whatever is returned here with
         * the id from the verified token, so the request can never dictate the caller's identity; the fallback
         * only matters where the aspect is switched off, such as tests that drive controllers directly.
         */
        @Override
        public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                      NativeWebRequest webRequest, WebDataBinderFactory binderFactory)
                throws Exception {
            String value = webRequest.getParameter(USER_ID);
            if (value == null || value.isBlank() || binderFactory == null) {
                return null;
            }
            WebDataBinder binder = binderFactory.createBinder(webRequest, null, USER_ID);
            return binder.convertIfNecessary(value, parameter.getParameterType(), parameter);
        }

        private static boolean isJwtAuthenticated(MethodParameter parameter) {
            Method method = parameter.getMethod();
            return (method != null && AnnotatedElementUtils.hasAnnotation(method, JwtAuthenticated.class))
                    || AnnotatedElementUtils.hasAnnotation(parameter.getContainingClass(), JwtAuthenticated.class)
                    || AnnotatedElementUtils.hasAnnotation(parameter.getDeclaringClass(), JwtAuthenticated.class);
        }
    }
}
