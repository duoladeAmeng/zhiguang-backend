package com.dyc.profile.service;



import com.dyc.profile.dto.ProfilePatchRequest;
import com.dyc.profile.dto.ProfileResponse;
import com.dyc.user.domain.User;

import java.util.Optional;

/**
 * 个人资料业务接口。
 */
public interface ProfileService {

    Optional<User> getById(long userId);

    ProfileResponse updateProfile(long userId, ProfilePatchRequest req);

    ProfileResponse updateAvatar(long userId, String avatarUrl);
}