package com.example.springsecuritydemo.pojo;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

@TableName("t_role")
@Data
public class Role {

    private Integer id;

    private String roleName;
}
