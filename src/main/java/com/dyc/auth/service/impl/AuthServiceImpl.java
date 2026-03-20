package com.dyc.auth.service.impl;

import com.dyc.auth.audit.LoginLogService;
import com.dyc.auth.config.AuthProperties;
import com.dyc.auth.dto.*;
import com.dyc.auth.model.ClientInfo;
import com.dyc.auth.model.IdentifierType;
import com.dyc.auth.service.AuthService;
import com.dyc.auth.token.JwtService;
import com.dyc.auth.token.RefreshTokenStore;
import com.dyc.auth.token.TokenPair;
import com.dyc.auth.util.IdentifierValidator;
import com.dyc.auth.verification.*;
import com.dyc.common.exception.BusinessException;
import com.dyc.common.exception.ErrorCode;
import com.dyc.user.domain.User;
import com.dyc.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final VerificationService verificationService;
    private final AuthProperties authProperties;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenStore refreshTokenStore;
    private final LoginLogService loginLogService;
    /**
     * 发送验证码并返回过期信息。
     * <p>
     * 注册场景要求标识不存在；登录/重置密码场景要求标识存在。
     *
     * @param request 请求体，包含：标识类型与值、场景。
     * @return 响应体，包含目标标识、场景与验证码过期秒数。
     * @throws BusinessException 当标识格式错误或存在性不符合场景要求时抛出。
     */
    public SendCodeResponse sendCode(SendCodeRequest request) {
        //校验手机号 or 邮箱
        validateIdentifier(request.identifierType(), request.identifier());
        //标准化
        String normalized = normalizeIdentifier(request.identifierType(), request.identifier());
        boolean exists = identifierExists(request.identifierType(), normalized);
        if (request.scene() == VerificationScene.REGISTER && exists) {
            throw new BusinessException(ErrorCode.IDENTIFIER_EXISTS);
        }
        if ((request.scene() == VerificationScene.LOGIN || request.scene() == VerificationScene.RESET_PASSWORD) && !exists) {
            throw new BusinessException(ErrorCode.IDENTIFIER_NOT_FOUND);
        }
        SendCodeResult result = verificationService.sendCode(request.scene(), normalized);
        return new SendCodeResponse(result.identifier(), result.scene(), result.expireSeconds());
    }

    /**
     * 校验标识（手机号/邮箱）的格式。
     *
     * @param type       标识类型：PHONE 或 EMAIL。
     * @param identifier 标识值。
     * @throws BusinessException 当格式不合法时抛出。
     */
    private void validateIdentifier(IdentifierType type, String identifier) {
        if (type == IdentifierType.PHONE && !IdentifierValidator.isValidPhone(identifier)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "手机号格式错误");
        }
        if (type == IdentifierType.EMAIL && !IdentifierValidator.isValidEmail(identifier)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST, "邮箱格式错误");
        }
    }

    /**
     * 标准化标识文本：手机号去空格、邮箱转小写并去空格。
     *
     * @param type       标识类型：PHONE 或 EMAIL。
     * @param identifier 原始标识文本。
     * @return 标准化后的标识文本。
     */
    private String normalizeIdentifier(IdentifierType type, String identifier) {
        return switch (type) {
            case PHONE -> identifier.trim();
            case EMAIL -> identifier.trim().toLowerCase(Locale.ROOT);
        };
    }

    /**
     * 判断标识是否已存在。
     *
     * @param type       标识类型：PHONE 或 EMAIL。
     * @param identifier 标识值（需为标准化格式）。
     * @return 是否存在。
     */
    private boolean identifierExists(IdentifierType type, String identifier) {
        return switch (type) {
            case PHONE -> userService.existsByPhone(identifier);
            case EMAIL -> userService.existsByEmail(identifier);
        };
    }


    /**
     * 注册用户并签发令牌。
     * <p>
     * 验证标识与验证码，创建用户（可选设置密码），记录审计，签发令牌对并保存刷新令牌白名单。
     *
     * @param request    注册请求，包含：标识类型与值、验证码、可选密码、是否同意协议。
     * @param clientInfo 客户端信息（IP/UA），用于登录审计。
     * @return 认证响应，包含用户信息与令牌对。
     * @throws BusinessException 当未同意协议、标识冲突、验证码失败、密码不合规时抛出。
     */
    @Override
    public AuthResponse register(RegisterRequest request, ClientInfo clientInfo) {
        if (!request.agreeTerms()) {
            throw new BusinessException(ErrorCode.TERMS_NOT_ACCEPTED);
        }
        // 验证标识 邮箱手机号的格式是不是正确
        validateIdentifier(request.identifierType(), request.identifier());
        // 标准化标识 去除左右空格 邮箱字母转小写
        String identifier = normalizeIdentifier(request.identifierType(), request.identifier());
        // 判断用户是否已经注册
        if (identifierExists(request.identifierType(), identifier)) {
            throw new BusinessException(ErrorCode.IDENTIFIER_EXISTS);
        }
        //检查验证码
        ensureVerificationSuccess(verificationService.verify(VerificationScene.REGISTER, identifier, request.code()));

        User user = User.builder()
                .phone(request.identifierType() == IdentifierType.PHONE ? identifier : null)
                .email(request.identifierType() == IdentifierType.EMAIL ? identifier : null)
                .nickname(generateNickname())
                .avatar("https://static.zhiguang.cn/default-avatar.png")
                .bio(null)
                .tagsJson("[]")
                .build();

        if (StringUtils.hasText(request.password())) {
            validatePassword(request.password());
            user.setPasswordHash(passwordEncoder.encode(request.password().trim()));
        }

        userService.createUser(user);
        TokenPair tokenPair = jwtService.issueTokenPair(user);
        storeRefreshToken(user.getId(), tokenPair);
        loginLogService.record(user.getId(), identifier, "REGISTER", clientInfo.ip(), clientInfo.userAgent(), "SUCCESS");

        return new AuthResponse(mapUser(user), mapToken(tokenPair));
    }

    /**
     * 保证验证码校验成功，否则按状态抛出对应业务异常。
     *
     * @param result 验证码校验结果。
     */
    private void ensureVerificationSuccess(VerificationCheckResult result) {
        if (result.isSuccess()) {
            return;
        }
        VerificationCodeStatus status = result.status();
        if (status == VerificationCodeStatus.NOT_FOUND || status == VerificationCodeStatus.EXPIRED) {
            throw new BusinessException(ErrorCode.VERIFICATION_NOT_FOUND);
        }
        if (status == VerificationCodeStatus.MISMATCH) {
            throw new BusinessException(ErrorCode.VERIFICATION_MISMATCH);
        }
        if (status == VerificationCodeStatus.TOO_MANY_ATTEMPTS) {
            throw new BusinessException(ErrorCode.VERIFICATION_TOO_MANY_ATTEMPTS);
        }
        throw new BusinessException(ErrorCode.BAD_REQUEST, "验证码校验失败");
    }


    /**
     * 校验密码策略：非空、最小长度、必须包含字母和数字。
     *
     * @param password 明文密码。
     * @throws BusinessException 当密码不满足策略时抛出。
     */
    private void validatePassword(String password) {
        if (!StringUtils.hasText(password)) {
            throw new BusinessException(ErrorCode.PASSWORD_POLICY_VIOLATION, "密码不能为空");
        }
        String trimmed = password.trim();
        if (trimmed.length() <authProperties.getPassword().getMinLength()) {
            throw new BusinessException(ErrorCode.PASSWORD_POLICY_VIOLATION, "密码长度至少" + authProperties.getPassword().getMinLength() + "位");
        }
        boolean hasLetter = trimmed.chars().anyMatch(Character::isLetter);
        boolean hasDigit = trimmed.chars().anyMatch(Character::isDigit);
        if (!hasLetter || !hasDigit) {
            throw new BusinessException(ErrorCode.PASSWORD_POLICY_VIOLATION, "密码需包含字母和数字");
        }
    }

    
    /**
     * 生成默认昵称。
     *
     * @return 随机昵称字符串。
     */
    private String generateNickname() {
        return "知光用户" + UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * 存储刷新令牌白名单记录。
     *
     * @param userId    用户 ID。
     * @param tokenPair 令牌对（含刷新令牌 ID 与过期时间）。
     */
    private void storeRefreshToken(Long userId, TokenPair tokenPair) {
        Duration ttl = Duration.between(Instant.now(), tokenPair.refreshTokenExpiresAt());
        if (ttl.isNegative()) {
            ttl = Duration.ZERO;
        }
        refreshTokenStore.storeToken(userId, tokenPair.refreshTokenId(), ttl);
    }

    /**
     * 映射用户实体到响应对象。
     *
     * @param user 用户实体。
     * @return 用户响应。
     */
    private AuthUserResponse mapUser(User user) {
        return new AuthUserResponse(
                user.getId(),
                user.getNickname(),
                user.getAvatar(),
                user.getPhone(),
                user.getZgId(),
                user.getBirthday(),
                user.getSchool(),
                user.getBio(),
                user.getGender(),
                user.getTagsJson()
        );
    }

    /**
     * 映射令牌对到响应对象。
     *
     * @param tokenPair 令牌对。
     * @return 令牌响应。
     */
    private TokenResponse mapToken(TokenPair tokenPair) {
        return new TokenResponse(tokenPair.accessToken(), tokenPair.accessTokenExpiresAt(), tokenPair.refreshToken(), tokenPair.refreshTokenExpiresAt());
    }




    /**
     * 登录并签发令牌。
     * <p>
     * 支持密码或验证码两种认证通道，流程如下：
     * <ol>
     *     <li>校验标识（手机号/邮箱）格式合法性</li>
     *     <li>标准化标识文本（手机号去空格、邮箱转小写）</li>
     *     <li>根据标识查找用户，不存在则抛出异常</li>
     *     <li>认证方式判断：
     *         <ul>
     *             <li>密码通道：校验密码哈希匹配性，失败记录失败日志并抛出异常</li>
     *             <li>验证码通道：校验验证码有效性，失败抛出对应异常</li>
     *         </ul>
     *     </li>
     *     <li>认证成功：签发 JWT 令牌对（访问令牌 + 刷新令牌）</li>
     *     <li>保存刷新令牌白名单记录</li>
     *     <li>记录成功登录审计日志</li>
     * </ol>
     *
     * @param request    登录请求，包含：
     *                   - identifierType: 标识类型（PHONE/EMAIL）
     *                   - identifier: 标识值（手机号/邮箱）
     *                   - password: 密码（可选，密码通道时必填）
     *                   - code: 验证码（可选，验证码通道时必填）
     * @param clientInfo 客户端信息，包含：
     *                   - ip: 客户端 IP 地址
     *                   - userAgent: 客户端 User-Agent 字符串
     * @return 认证响应，包含：
     *         - user: 用户信息（ID、昵称、头像等）
     *         - token: 令牌对（访问令牌、刷新令牌及过期时间）
     * @throws BusinessException 以下情况抛出：
     *         - IDENTIFIER_NOT_FOUND: 标识不存在
     *         - INVALID_CREDENTIALS: 密码错误
     *         - VERIFICATION_NOT_FOUND/VERIFICATION_MISMATCH/VERIFICATION_TOO_MANY_ATTEMPTS: 验证码相关错误
     *         - BAD_REQUEST: 未提供密码或验证码
     */
    public AuthResponse login(LoginRequest request, ClientInfo clientInfo) {
        // 1. 校验标识格式合法性（手机号/邮箱）
        validateIdentifier(request.identifierType(), request.identifier());
        // 2. 标准化标识文本（手机号去空格、邮箱转小写）
        String identifier = normalizeIdentifier(request.identifierType(), request.identifier());
        // 3. 根据标识查找用户
        Optional<User> userOptional = findUserByIdentifier(request.identifierType(), identifier);
        if (userOptional.isEmpty()) {
            throw new BusinessException(ErrorCode.IDENTIFIER_NOT_FOUND);
        }
        User user = userOptional.get();
        String channel;
        // 4. 认证方式判断与验证
        if (StringUtils.hasText(request.password())) {
            // 4.1 密码通道
            channel = "PASSWORD";
            // 校验密码：检查是否设置过密码且哈希匹配
            if (!StringUtils.hasText(user.getPasswordHash()) || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
                // 密码错误，记录失败日志
                loginLogService.record(user.getId(), identifier, channel, clientInfo.ip(), clientInfo.userAgent(), "FAILED");
                throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
            }
        } else if (StringUtils.hasText(request.code())) {
            // 4.2 验证码通道
            channel = "CODE";
            // 校验验证码，失败会抛出对应异常
            ensureVerificationSuccess(verificationService.verify(VerificationScene.LOGIN, identifier, request.code()));
        } else {
            // 4.3 未提供有效认证凭据
            throw new BusinessException(ErrorCode.BAD_REQUEST, "请提供验证码或密码");
        }
        // 5. 认证成功后签发 JWT 令牌对
        TokenPair tokenPair = jwtService.issueTokenPair(user);
        // 6. 保存刷新令牌到白名单（用于后续刷新访问令牌）
        storeRefreshToken(user.getId(), tokenPair);
        // 7. 记录成功登录审计日志
        loginLogService.record(user.getId(), identifier, channel, clientInfo.ip(), clientInfo.userAgent(), "SUCCESS");
        // 8. 返回认证响应（用户信息 + 令牌对）
        return new AuthResponse(mapUser(user), mapToken(tokenPair));
    }



    /**
     * 根据标识查找用户。
     *
     * @param type       标识类型：PHONE 或 EMAIL。
     * @param identifier 标识值（需为标准化格式）。
     * @return 用户 Optional。
     */
    private Optional<User> findUserByIdentifier(IdentifierType type, String identifier) {
        return switch (type) {
            case PHONE -> userService.findByPhone(identifier);
            case EMAIL -> userService.findByEmail(identifier);
        };
    }

    /**
     * 根据 ID 查找用户。
     *
     * @param userId 用户 ID。
     * @return 用户 Optional。
     */
    private Optional<User> findUserById(long userId) {
        return userService.findById(userId);
    }


    /**
     * 使用验证码重置密码并使刷新令牌失效。
     *
     * @param request 重置请求，包含：标识类型与值、验证码、新密码。
     * @throws BusinessException 当标识不存在、验证码失败或密码策略不满足时抛出。
     */
    public void resetPassword(PasswordResetRequest request) {
        validateIdentifier(request.identifierType(), request.identifier());
        validatePassword(request.newPassword());
        String identifier = normalizeIdentifier(request.identifierType(), request.identifier());
        User user = findUserByIdentifier(request.identifierType(), identifier)
                .orElseThrow(() -> new BusinessException(ErrorCode.IDENTIFIER_NOT_FOUND));
        ensureVerificationSuccess(verificationService.verify(VerificationScene.RESET_PASSWORD, identifier, request.code()));
        user.setPasswordHash(passwordEncoder.encode(request.newPassword().trim()));
        userService.updatePassword(user);
        refreshTokenStore.revokeAll(user.getId());
    }

    /**
     * 查询用户概要信息。
     *
     * @param userId 用户 ID。
     * @return 用户概要响应。
     * @throws BusinessException 当用户不存在时抛出。
     */
    public AuthUserResponse me(long userId) {
        User user = findUserById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.IDENTIFIER_NOT_FOUND));
        return mapUser(user);
    }


    /**
     * 使用刷新令牌获取新的令牌对。
     * <p>
     * 校验刷新令牌类型与白名单有效性，签发新令牌后撤销旧刷新令牌并存储新令牌。
     *
     * @param request 刷新请求，包含：refreshToken。
     * @return 新的令牌响应。
     * @throws BusinessException 当刷新令牌无效或用户不存在时抛出。
     */
    public TokenResponse refresh(TokenRefreshRequest request) {
        // 解码刷新令牌，提取 JWT 信息用于后续验证
        Jwt jwt = decodeRefreshToken(request.refreshToken());

        // 验证令牌类型是否为 refresh 类型，防止访问令牌被误用为刷新令牌
        if (!Objects.equals("refresh", jwtService.extractTokenType(jwt))) {
            throw new BusinessException(ErrorCode.REFRESH_TOKEN_INVALID);
        }

        // 从 JWT 中提取用户 ID 和令牌 ID，用于后续的用户查询和令牌验证
        long userId = jwtService.extractUserId(jwt);
        String tokenId = jwtService.extractTokenId(jwt);

        // 检查刷新令牌是否在白名单中且未过期、未被撤销
        if (!refreshTokenStore.isTokenValid(userId, tokenId)) {
            throw new BusinessException(ErrorCode.REFRESH_TOKEN_INVALID);
        }

        // 根据用户 ID 查询用户信息，确保用户仍然存在
        User user = findUserById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.IDENTIFIER_NOT_FOUND));

        // 为认证用户签发新的访问令牌和刷新令牌对
        TokenPair tokenPair = jwtService.issueTokenPair(user);

        // 撤销旧的刷新令牌，实现刷新令牌的单次使用特性，提高安全性
        refreshTokenStore.revokeToken(userId, tokenId);

        // 将新的刷新令牌存储到白名单中，以便后续刷新操作
        storeRefreshToken(userId, tokenPair);

        // 将令牌对转换为响应对象返回给客户端
        return mapToken(tokenPair);
    }


    /**
     * 解码刷新令牌，失败时抛业务异常。
     *
     * @param refreshToken 刷新令牌字符串。
     * @return 解析得到的 JWT。
     * @throws BusinessException 当刷新令牌无法解析时抛出。
     */
    private Jwt decodeRefreshToken(String refreshToken) {
        try {
            return jwtService.decode(refreshToken);
        } catch (JwtException ex) {
            throw new BusinessException(ErrorCode.REFRESH_TOKEN_INVALID);
        }
    }
}
