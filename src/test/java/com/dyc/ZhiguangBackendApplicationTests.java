package com.dyc;
import java.time.Instant;

import com.dyc.user.domain.User;
import com.dyc.user.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.zhipuai.api.ZhiPuAiApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import reactor.core.publisher.Flux;

import java.time.LocalDate;

@SpringBootTest
class ZhiguangBackendApplicationTests {

//    @Autowired
//    private UserMapper userMapper;
//    @Test
//    void testDb(){
//        System.out.println("测试数据库连接");
//
//        User user = new User();
//        user.setId(0L);
//        user.setPhone("1");
//        user.setEmail("3");
//        user.setPasswordHash("4444444444");
//        user.setNickname("vv");
//        user.setAvatar("ffffffff");
//        user.setBio("ff");
//        user.setZgId("e");
//        user.setGender("e");
//        user.setBirthday(LocalDate.now());
//        user.setSchool("e");
//        user.setTagsJson("{\"key\":\"value\"}");
//        user.setCreatedAt(Instant.now());
//        user.setUpdatedAt(Instant.now());
//
//        userMapper.addUser(user);
//    }

    @Autowired
    private ChatClient chatClient;
    @Test
    void testAI() throws InterruptedException {

        String msg = "帮我规划巴黎旅行计划";

        // 使用 CountDownLatch 等待流结束
        java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);

        chatClient.prompt()
                .user(msg)
                .stream()
                .content()
                .doOnComplete(() -> {
                    System.out.println("\n--- 生成结束 ---");
                    latch.countDown(); // 计数减 1，释放锁
                })
                .doOnError(e -> {
                    e.printStackTrace();
                    latch.countDown();
                })
                .subscribe(System.out::print);

        // 阻塞当前测试线程，直到流完成或超时 (例如等待 60 秒)
        latch.await(60, java.util.concurrent.TimeUnit.SECONDS);
    }
}
