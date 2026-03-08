package com.dyc.user.mapper;

import com.dyc.user.domain.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {

    public boolean addUser(User user);
}
