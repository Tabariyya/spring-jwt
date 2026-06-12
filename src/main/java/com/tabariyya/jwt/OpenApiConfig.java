package com.tabariyya.jwt;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.AnnotatedElement;
import java.util.List;

@Configuration
public class OpenApiConfig {
    @Bean
    public OpenAPI customOpenAPI() {
        // Define the Security Scheme
        SecurityScheme bearerAuthScheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT");

        // Add the Security Scheme to the OpenAPI Components
        Components components = new Components()
                .addSecuritySchemes("BearerAuth", bearerAuthScheme);

        // Create the Security Requirement
        SecurityRequirement securityRequirement = new SecurityRequirement()
                .addList("BearerAuth");

        // Define the server
        Server defaultServer = new Server()
                .url("/")
                .description("Default Server URL");

        // Build the OpenAPI object with server configuration
        return new OpenAPI()
                .components(components)
                .addSecurityItem(securityRequirement)
                .addServersItem(defaultServer)
                .info(new Info()
                        .title("My API")
                        .version("1.0")
                        .description("API Documentation with Bearer Authentication"));
    }


    @Bean
    public OperationCustomizer hideUserIdParameterIfJwtAuthenticated() {
        return (Operation operation, HandlerMethod handlerMethod) -> {
            AnnotatedElement methodOrClass = handlerMethod.getMethod();
            if (methodOrClass.isAnnotationPresent(JwtAuthenticated.class)
                    || handlerMethod.getBeanType().isAnnotationPresent(JwtAuthenticated.class)) {

                List<Parameter> params = operation.getParameters();
                if (params != null) {
                    params.removeIf(p -> "userId".equals(p.getName()));
                }
            }
            return operation;
        };
    }

}