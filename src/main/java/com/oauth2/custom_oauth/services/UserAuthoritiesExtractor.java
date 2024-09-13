package com.oauth2.custom_oauth.services;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class UserAuthoritiesExtractor implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    // @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        System.out.println(jwt);
        return null;
    }

}
