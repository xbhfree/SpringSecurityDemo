package com.example.springsecuritydemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
@Controller
public class CsrfController {
    @GetMapping("/update_token")
    public String getToken(Model model){
        model.addAttribute("msg","hello");
        return "/csrf_token";
    }
}
