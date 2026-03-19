package com.dyc.auth.audit;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface LoginLogMapper {

    @Insert("INSERT INTO login_logs(id, user_id, identifier, channel, ip, user_agent, status, created_at) VALUES (#{log.id}, #{log.userId}, #{log.identifier}, #{log.channel}, #{log.ip}, #{log.userAgent}, #{log.status}, #{log.createdAt})")
    void insert(@Param("log") LoginLog log);
}

