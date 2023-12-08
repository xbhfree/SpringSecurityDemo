package com.example.springsecuritydemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorController {
    /*@GetMapping("/403")
    public String accessDenied(Model model) {
        model.addAttribute("403","无权限");
        return "access-denied";
    }*/
}
