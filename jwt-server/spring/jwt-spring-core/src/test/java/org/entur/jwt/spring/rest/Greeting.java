package org.entur.jwt.spring.rest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import javax.validation.constraints.NotNull;

import org.springframework.security.core.GrantedAuthority;

public class Greeting {

    private long id;
    @NotNull
    private String content;

    private String className;
    private List<String> authorities = new ArrayList<>();

    public Greeting() {
    }

    public Greeting(long id, String content) {
        this.id = id;
        this.content = content;
    }

    public Greeting(long id, String content, Class<?> argument, Collection<GrantedAuthority> authorities) {
        this.id = id;
        this.content = content;
        if (argument != null) {
            this.className = argument.getName();
        }
        if (authorities != null) {
            this.authorities = authorities.stream().map(a -> a.getAuthority()).collect(Collectors.toList());
        }
    }

    public long getId() {
        return id;
    }

    public String getContent() {
        return content;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public void setId(long id) {
        this.id = id;
    }

    public void setContent(String content) {
        this.content = content;
    }
}