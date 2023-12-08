package com.example.springsecuritydemo.service;

import cn.hutool.core.collection.CollUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.springsecuritydemo.mapper.PermissionMapper;
import com.example.springsecuritydemo.mapper.RoleMapper;
import com.example.springsecuritydemo.mapper.UserMapper;
import com.example.springsecuritydemo.pojo.Permission;
import com.example.springsecuritydemo.pojo.Role;
import com.example.springsecuritydemo.pojo.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MyUserDetailService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;
    @Autowired
    private RoleMapper roleMapper;
    @Autowired
    private PermissionMapper permissionMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        userQueryWrapper.eq("username",username);
        User user = userMapper.selectOne(userQueryWrapper);
        if (user == null) {
            throw new RuntimeException("用户不存在");
        }
        List<Role> roles = roleMapper.getRoleWithUserId(user.getId());
        if (roles != null){
            user.setRoles(roles);
            List<Permission> plist = new ArrayList<>();
            for (Role role : roles) {
                List<Permission> permissionWithRoleId = permissionMapper.getPermissionWithRoleId(role.getId());
                plist.addAll(permissionWithRoleId);
            }
            if (plist != null){
                ArrayList<Permission> distinct = CollUtil.distinct(plist);
                user.setPermissions(distinct);
            }
        }
        
        System.out.println(user);
        return user;
    }
}
