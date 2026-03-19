package com.dyc.auth.service;

import com.dyc.auth.dto.AuthResponse;
import com.dyc.auth.dto.RegisterRequest;
import com.dyc.auth.dto.SendCodeRequest;
import com.dyc.auth.dto.SendCodeResponse;
import com.dyc.auth.model.ClientInfo;

public interface AuthService {

    public SendCodeResponse sendCode(SendCodeRequest request);
    AuthResponse register(RegisterRequest request, ClientInfo clientInfo);
}
