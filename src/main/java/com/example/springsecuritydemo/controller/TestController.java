package com.example.springsecuritydemo.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("hello")
    public String hello(){
        return "hello security";
    }

    @Secured({"ROLE_ADMIN"})
    @GetMapping("helloAdmin")
    public String helloAdmin(){
        return "hello ROLE_ADMIN";
    }


    @GetMapping("helloWrite")
    @PreAuthorize("hasAnyAuthority('write')")
    public String helloWrite(){
        return "hello Write";
    }

}
