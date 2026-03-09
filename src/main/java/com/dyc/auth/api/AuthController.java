package com.dyc.auth.api;

import com.dyc.auth.config.AuthProperties;
import com.dyc.auth.dto.SendCodeRequest;
import com.dyc.auth.dto.SendCodeResponse;
import com.dyc.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuthProperties authProperties;


    /**
     * 发送短信/邮箱验证码。
     * <p>
     * 根据场景（注册、登录、重置密码）向指定标识（手机号或邮箱）发送一次性验证码。
     *
     * @param request 请求体，包含：
     *                - identifierType：标识类型，PHONE 或 EMAIL；
     *                - identifier：手机号或邮箱地址；
     *                - scene：验证码使用场景（REGISTER/LOGIN/RESET_PASSWORD）。
     * @return 响应体，包含目标标识、场景以及验证码过期秒数。
     */
    @PostMapping("/send-code")
    public SendCodeResponse sendCode(@Valid @RequestBody SendCodeRequest request) {
        return authService.sendCode(request);
    }

    /**
     * 注册新用户并自动登录。
     * <p>
     * 验证标识与验证码后创建用户，若提供密码则进行复杂度校验并保存密码哈希；成功后签发 Access/Refresh Token。
     *
     * @param request     请求体，包含：标识类型与值、验证码、可选密码、是否同意协议。
     * @param httpRequest 用于解析客户端信息（IP 与 User-Agent），记录审计日志。
     * @return 认证响应，包含用户信息与令牌对。
     */
    @PostMapping("/register")
    public AuthResponse register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        return authService.register(request, resolveClient(httpRequest));
    }

}
