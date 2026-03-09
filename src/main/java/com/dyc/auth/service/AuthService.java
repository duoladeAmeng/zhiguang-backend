package com.dyc.auth.service;

import com.dyc.auth.dto.SendCodeRequest;
import com.dyc.auth.dto.SendCodeResponse;

public interface AuthService {

    public SendCodeResponse sendCode(SendCodeRequest request);
}
