package com.example.springsecuritydemo;

import com.example.springsecuritydemo.mapper.PermissionMapper;
import com.example.springsecuritydemo.mapper.RoleMapper;
import com.example.springsecuritydemo.pojo.Permission;
import com.example.springsecuritydemo.pojo.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootTest
class SpringSecurityDemoApplicationTests {

    @Test
    void contextLoads() {
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println(encoder.encode("321"));
    }
    @Autowired
    private RoleMapper roleMapper;
    @Autowired
    private PermissionMapper permissionMapper;
    @Test
    void test(){
        List<Permission> permissionWithRoleId = permissionMapper.getPermissionWithRoleId(1);
        System.out.println(permissionWithRoleId);
    }

}
