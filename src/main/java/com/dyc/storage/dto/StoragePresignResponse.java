package com.dyc.storage.dto;


import java.util.Map;

/**
 * 预签名直传响应。
 * 用于返回对象存储的预签名上传 URL 及相关信息。
 *
 * @param objectKey 对象在存储桶中的唯一标识键
 * @param putUrl 预签名的上传 URL，客户端可使用此 URL 直接上传文件
 * @param headers 上传时需要携带的 HTTP 请求头
 * @param expiresIn 预签名 URL 的有效期（秒）
 */
public record StoragePresignResponse(
        /**
         * 对象在存储桶中的唯一标识键。
         */
        String objectKey,

        /**
         * 预签名的上传 URL。
         * 客户端可使用此 URL 直接上传文件到对象存储。
         */
        String putUrl,

        /**
         * 上传时需要携带的 HTTP 请求头。
         * 包含 Content-Type、Content-MD5 等验证和元数据信息。
         */
        Map<String, String> headers,

        /**
         * 预签名 URL 的有效期，单位为秒。
         * 超过有效期后，该 URL 将失效。
         */
        int expiresIn
) {}

