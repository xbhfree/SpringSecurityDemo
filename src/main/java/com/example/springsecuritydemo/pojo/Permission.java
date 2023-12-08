package com.example.springsecuritydemo.pojo;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

@TableName("t_permission")
@Data
public class Permission {
    private Integer id;

    private String permName;
}
