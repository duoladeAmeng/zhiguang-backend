package com.dyc.auth.verification;

/**
 * 验证码使用场景。
 * <p>
 *     验证码场景，对应不同的业务场景。
 *     登录、注册、重置密码场景使用。
 */

public enum VerificationScene {
    REGISTER,
    LOGIN,
    RESET_PASSWORD
}
