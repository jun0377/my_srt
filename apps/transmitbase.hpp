/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

#ifndef INC_SRT_COMMON_TRANMITBASE_HPP
#define INC_SRT_COMMON_TRANMITBASE_HPP

#include <string>
#include <memory>
#include <vector>
#include <iostream>
#include <stdexcept>
#include "srt.h"
#include "uriparser.hpp"
#include "apputil.hpp"
#include "statswriter.hpp"

typedef std::vector<char> bytevector;
extern bool transmit_total_stats;
extern bool g_stats_are_printed_to_stdout;
extern unsigned long transmit_bw_report;
extern unsigned long transmit_stats_report;
extern unsigned long transmit_chunk_size;

struct MediaPacket
{
    bytevector payload;
    int64_t time = 0;

    MediaPacket(bytevector&& src) : payload(std::move(src)) {}
    MediaPacket(bytevector&& src, int64_t stime) : payload(std::move(src)), time(stime) {}

    MediaPacket(size_t payload_size) : payload(payload_size), time(0) {}
    MediaPacket(const bytevector& src) : payload(src) {}
    MediaPacket(const bytevector& src, int64_t stime) : payload(src), time(stime) {}
    MediaPacket() {}
};

extern std::shared_ptr<SrtStatsWriter> transmit_stats_writer;

class Location
{
public:
    // URI解析器
    UriParser uri;
    Location() {}
};

// 抽象类
class Source: public Location
{
public:
    // 读取指定大小的数据到pkt中
    virtual int  Read(size_t chunk, MediaPacket& pkt, std::ostream &out_stats = std::cout) = 0;
    // 源是否已经打开
    virtual bool IsOpen() = 0;
    // 源是否已经读取完毕
    virtual bool End() = 0;
    // 根据URI创建源
    static std::unique_ptr<Source> Create(const std::string& url);
    // 关闭源
    virtual void Close() {}
    // 虚析构
    virtual ~Source() {}

    // 自定义异常类，处理读到末尾的情况
    class ReadEOF: public std::runtime_error
    {
    public:
        ReadEOF(const std::string& fn): std::runtime_error( "EOF while reading file: " + fn )
        {
        }
    };

    // 获取源对应的SRTSOCKET
    virtual SRTSOCKET GetSRTSocket() const { return SRT_INVALID_SOCK; }
    // 获取源对应的SYSSOCKET
    virtual int GetSysSocket() const { return -1; }
    // 是否接受新的连接
    virtual bool AcceptNewClient() { return false; }
};

class Target: public Location
{
public:
    virtual int  Write(const char* data, size_t size, int64_t src_time, std::ostream &out_stats = std::cout) = 0;
    virtual bool IsOpen() = 0;
    virtual bool Broken() = 0;
    virtual void Close() {}
    virtual size_t Still() { return 0; }
    static std::unique_ptr<Target> Create(const std::string& url);
    virtual ~Target() {}

    virtual SRTSOCKET GetSRTSocket() const { return SRT_INVALID_SOCK; }
    virtual int GetSysSocket() const { return -1; }
    virtual bool AcceptNewClient() { return false; }
};

#endif
