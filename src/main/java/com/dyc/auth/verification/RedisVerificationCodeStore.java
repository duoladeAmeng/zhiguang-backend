package com.dyc.auth.verification;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.RedisSystemException;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * 基于 Redis 的验证码存储实现。
 * <p>
 * 使用 Hash 结构保存 `code`、`maxAttempts` 与 `attempts`，TTL 控制有效期。
 * 校验时支持尝试计数与错误状态返回，成功后删除键以防重用。
 */

@Component
public class RedisVerificationCodeStore implements VerificationCodeStore{
    private static final String FIELD_CODE = "code";
    private static final String FIELD_MAX_ATTEMPTS = "maxAttempts";
    private static final String FIELD_ATTEMPTS = "attempts";

    private final StringRedisTemplate redisTemplate;

    public RedisVerificationCodeStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 保存验证码到 Redis Hash，并设置 TTL。
     *
     * @param scene       场景名称。
     * @param identifier  标识（手机号或邮箱）。
     * @param code        验证码字符串。
     * @param ttl         有效期。
     * @param maxAttempts 最大尝试次数。
     * @throws RedisSystemException 保存失败时抛出。
     */
    @Override
    public void saveCode(String scene, String identifier, String code, Duration ttl, int maxAttempts) {
        String key = buildKey(scene, identifier);
        HashOperations<String, String, String> ops = redisTemplate.opsForHash();
        try {
            ops.put(key, FIELD_CODE, code);
            ops.put(key, FIELD_MAX_ATTEMPTS, String.valueOf(maxAttempts));
            ops.put(key, FIELD_ATTEMPTS, "0");
            redisTemplate.expire(key, ttl);
        } catch (DataAccessException ex) {
            throw new RedisSystemException("Failed to save verification code", ex);
        }
    }
    /**
     * 生成验证码的 Redis 键名。
     *
     * @param scene      场景名称。
     * @param identifier 标识（手机号或邮箱）。
     * @return 键名字符串。
     */
    private static String buildKey(String scene, String identifier) {
        return "auth:code:%s:%s".formatted(scene, identifier);
    }


        /**
     * 校验验证码是否匹配，更新尝试计数并在成功时删除记录。
     * <p>
     * 校验流程如下：
     * <ol>
     *     <li>构建 Redis Key 并获取 Hash 结构中的完整数据</li>
     *     <li>检查记录是否存在：不存在返回 NOT_FOUND</li>
     *     <li>检查尝试次数是否已达上限：达到返回 TOO_MANY_ATTEMPTS</li>
     *     <li>验证码比对：
     *         <ul>
     *             <li>匹配：删除记录并返回 SUCCESS</li>
     *             <li>不匹配：递增尝试次数，判断是否触发上限</li>
     *         </ul>
     *     </li>
     *     <li>尝试次数达上限时：延长 TTL 至 30 分钟并返回 TOO_MANY_ATTEMPTS</li>
     *     <li>否则返回 MISMATCH 及当前尝试信息</li>
     * </ol>
     *
     * @param scene      场景名称，用于区分业务用途（如 LOGIN、REGISTER、RESET_PASSWORD）。
     * @param identifier 标识（手机号或邮箱），已标准化格式（手机号去空格、邮箱转小写）。
     * @param code       用户输入的验证码字符串。
     * @return 校验结果对象，包含：
     *         - status: 验证码状态（SUCCESS/NOT_FOUND/MISMATCH/TOO_MANY_ATTEMPTS）
     *         - attempts: 当前已尝试次数
     *         - maxAttempts: 最大允许尝试次数
     * @implNote Redis Hash 结构说明：
     *         - code: 存储的验证码值
     *         - maxAttempts: 最大尝试次数限制
     *         - attempts: 当前已尝试次数
     */
    @Override
    public VerificationCheckResult verify(String scene, String identifier, String code) {
        // 1. 构建 Redis Key：格式为 "auth:code:{scene}:{identifier}"
        String key = buildKey(scene, identifier);
        // 2. 获取 Redis Hash 操作对象
        HashOperations<String, String, String> ops = redisTemplate.opsForHash();
        // 3. 读取 Hash 中的所有字段（code、maxAttempts、attempts）
        Map<String, String> data = ops.entries(key);
        // 4. 记录不存在：验证码已过期或被使用
        if (data.isEmpty()) {
            return new VerificationCheckResult(VerificationCodeStatus.NOT_FOUND, 0, 0);
        }
        // 5. 提取存储的验证码和尝试次数配置
        String storedCode = data.get(FIELD_CODE);
        int maxAttempts = parseInt(data.get(FIELD_MAX_ATTEMPTS), 5);  // 默认 5 次
        int attempts = parseInt(data.get(FIELD_ATTEMPTS), 0);          // 默认 0 次

        // 6. 检查是否已超过最大尝试次数
        if (attempts >= maxAttempts) {
            return new VerificationCheckResult(VerificationCodeStatus.TOO_MANY_ATTEMPTS, attempts, maxAttempts);
        }

        // 7. 验证码比对
        if (Objects.equals(storedCode, code)) {
            // 7.1 匹配成功：立即删除记录，防止重复使用
            redisTemplate.delete(key);
            return new VerificationCheckResult(VerificationCodeStatus.SUCCESS, attempts, maxAttempts);
        }

        // 8. 匹配失败：递增尝试次数并更新 Redis
        int updatedAttempts = attempts + 1;
        ops.put(key, FIELD_ATTEMPTS, String.valueOf(updatedAttempts));

        // 9. 检查是否触发最大尝试次数限制
        if (updatedAttempts >= maxAttempts) {
            // 9.1 达到上限：延长 TTL 至 30 分钟（防止暴力破解）
            redisTemplate.expire(key, Duration.ofMinutes(30));
            return new VerificationCheckResult(VerificationCodeStatus.TOO_MANY_ATTEMPTS, updatedAttempts, maxAttempts);
        }

        // 10. 返回不匹配状态及当前尝试信息
        return new VerificationCheckResult(VerificationCodeStatus.MISMATCH, updatedAttempts, maxAttempts);
    }




    /**
     * 解析整数字符串，失败返回默认值。
     *
     * @param value        待解析字符串。
     * @param defaultValue 解析失败时的默认值。
     * @return 整数值。
     */
    private static int parseInt(String value, int defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    @Override
    public void invalidate(String scene, String identifier) {
        redisTemplate.delete(buildKey(scene, identifier));
    }
}
