package com.example.springsecuritydemo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.springsecuritydemo.pojo.User;

import java.util.List;

public interface UserMapper extends BaseMapper<User> {
    List<User> getUsersById(Integer uId);
}
