/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

#ifndef INC_SRT_URL_PARSER_H
#define INC_SRT_URL_PARSER_H

#include <string>
#include <map>
#include <cstdlib>
#include "utilities.h"


//++
// UriParser
//--

// URI解析器
class UriParser
{
// Construction
public:

    // URI类型: 文件路径/网络地址
    enum DefaultExpect { EXPECT_FILE, EXPECT_HOST };

    // 不同类型的源: 文件/UDP/TCP/SRT/RTMP/HTTP/RTP
    enum Type
    {
        UNKNOWN, FILE, UDP, TCP, SRT, RTMP, HTTP, RTP
    };

    // 构造函数，默认的URI类型是文件路径
    UriParser(const std::string& strUrl, DefaultExpect exp = EXPECT_FILE);
    // 默认构造函数，URI类型是未知的
    UriParser(): m_uriType(UNKNOWN) {}
    // 虚析构
    virtual ~UriParser(void);

    // Some predefined types
    // 获取URI类型
    Type type() const;

    // 定义一个代理类型,用以安全地访问和修改URI参数
    typedef MapProxy<std::string, std::string> ParamProxy;

// Operations
public:
    // 获取URI字符串
    std::string uri() const { return m_origUri; }
    // 获取URI 协议，如http/https/rtmp/rtsp/srt等
    std::string proto() const;
    // 获取scheme, 与proto()相同
    std::string scheme() const { return proto(); }
    // 获取URI 主机
    std::string host() const;
    // 获取URI 端口，字符串
    std::string port() const;
    // 获取URI 端口，数字
    unsigned short int portno() const;
    // 获取URI 主机:端口
    std::string hostport() const { return host() + ":" + port(); }
    // 获取URI 文件路径
    std::string path() const;
    // 查询URI指定地参数值
    std::string queryValue(const std::string& strKey) const;
    // 生成URI字符串
    std::string makeUri();
    // 重载[]运算符，用于访问和修改URI参数
    ParamProxy operator[](const std::string& key) { return ParamProxy(m_mapQuery, key); }
    // 获取URI 所有参数
    const std::map<std::string, std::string>& parameters() const { return m_mapQuery; }
    // URI参数列表迭代器
    typedef std::map<std::string, std::string>::const_iterator query_it;

private:
    // 解析URI字符串
    void Parse(const std::string& strUrl, DefaultExpect);

// Overridables
public:

// Overrides
public:

// Data
private:
    // 原始URI字符串
    std::string m_origUri;
    // URI 协议 
    std::string m_proto;
    // URI 主机
    std::string m_host;
    // URI 端口
    std::string m_port;
    // URI 路径
    std::string m_path;
    // 不同类型的源: 文件/UDP/TCP/SRT/RTMP/HTTP/RTP
    Type m_uriType;
    // 默认的URI类型
    DefaultExpect m_expect;

    std::map<std::string, std::string> m_mapQuery;
};

//#define TEST1 1

#endif // INC_SRT_URL_PARSER_H
