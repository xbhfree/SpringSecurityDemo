package com.example.springsecuritydemo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.springsecuritydemo.pojo.Role;

import java.util.List;

public interface RoleMapper extends BaseMapper<Role> {
    List<Role> getRoleWithUserId(Integer uId);
}
