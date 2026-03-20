package com.dyc.auth.service;

import com.dyc.auth.dto.*;
import com.dyc.auth.model.ClientInfo;
import jakarta.validation.Valid;

public interface AuthService {

    public SendCodeResponse sendCode(SendCodeRequest request);
    AuthResponse register(RegisterRequest request, ClientInfo clientInfo);

    AuthResponse login(@Valid LoginRequest request, ClientInfo clientInfo);

    void resetPassword(@Valid PasswordResetRequest request);

    AuthUserResponse me(long userId);

    TokenResponse refresh(@Valid TokenRefreshRequest request);
}
