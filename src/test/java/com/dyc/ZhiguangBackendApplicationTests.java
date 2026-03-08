package com.dyc;
import java.time.Instant;

import com.dyc.user.domain.User;
import com.dyc.user.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDate;

@SpringBootTest
class ZhiguangBackendApplicationTests {

    @Autowired
    private UserMapper userMapper;
    @Test
    void testDb(){
        System.out.println("测试数据库连接");

        User user = new User();
        user.setId(0L);
        user.setPhone("1");
        user.setEmail("3");
        user.setPasswordHash("4444444444");
        user.setNickname("vv");
        user.setAvatar("ffffffff");
        user.setBio("ff");
        user.setZgId("e");
        user.setGender("e");
        user.setBirthday(LocalDate.now());
        user.setSchool("e");
        user.setTagsJson("{\"key\":\"value\"}");
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());


        userMapper.addUser(user);
    }

}
