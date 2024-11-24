/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

#ifndef INC_SRT_COMMON_TRANSMITMEDIA_HPP
#define INC_SRT_COMMON_TRANSMITMEDIA_HPP

#include <string>
#include <map>
#include <stdexcept>

#include "transmitbase.hpp"
#include <udt.h> // Needs access to CUDTException

using namespace std;

// Trial version of an exception. Try to implement later an official
// interruption mechanism in SRT using this.

struct TransmissionError: public std::runtime_error
{
    TransmissionError(const std::string& arg):
        std::runtime_error(arg)
    {
    }
};

// SRT公共类
class SrtCommon
{
protected:

    // 传输方向，是发送还是接受，
    bool m_output_direction = false; //< Defines which of SND or RCV option variant should be used, also to set SRT_SENDER for output
    // 发送/接收超时
    int m_timeout = 0; //< enforces using SRTO_SNDTIMEO or SRTO_RCVTIMEO, depending on @a m_output_direction
    // 是否使用基于时间戳的数据包传递模式
    bool m_tsbpdmode = true;
    
    // 出站端口
    int m_outgoing_port = 0;
    // 连接模式:Listener/Caller/Rendezvous
    string m_mode;
    // 网络适配器,指定使用哪个网络接口
    string m_adapter;
    // URI中暂时没有进行处理的选项，便于后续扩展
    map<string, string> m_options; // All other options, as provided in the URI
    // SRT套接字
    SRTSOCKET m_sock = SRT_INVALID_SOCK;
    // SRT监听套接字
    SRTSOCKET m_bindsock = SRT_INVALID_SOCK;
    // SRT套接字是否可用
    bool IsUsable() { SRT_SOCKSTATUS st = srt_getsockstate(m_sock); return st > SRTS_INIT && st < SRTS_BROKEN; }
    // SRT连接是否正常
    bool IsBroken() { return srt_getsockstate(m_sock) > SRTS_CONNECTED; }

public:
    // 初始化参数
    void InitParameters(string host, map<string,string> par);
    // 创建一个SRTSOCKET，并开始监听
    void PrepareListener(string host, int port, int backlog);
    // 从其他SRTCmmon对象中获取资源
    void StealFrom(SrtCommon& src);
    // 是否接受新的客户端连接
    bool AcceptNewClient();

    // 获取SRTSOCKET
    SRTSOCKET Socket() const { return m_sock; }
    // 获取SRT监听套接字
    SRTSOCKET Listener() const { return m_bindsock; }
    // 关闭SRT套接字
    void Close();

protected:

    // 错误处理
    void Error(string src);
    // 初始化
    void Init(string host, int port, map<string,string> par, bool dir_output);

    // 连接后的配置
    virtual int ConfigurePost(SRTSOCKET sock);
    // 连接前的配置
    virtual int ConfigurePre(SRTSOCKET sock);

    // 打开客户端
    void OpenClient(string host, int port);
    // 准备客户端
    void PrepareClient();
    // 设置网络适配器，绑定SRT套接字到指定地址
    void SetupAdapter(const std::string& host, int port);
    // 连接客户端
    void ConnectClient(string host, int port);

    // 打开服务器
    void OpenServer(string host, int port)
    {
        // 准备监听
        PrepareListener(host, port, 1);
    }

    // 开启交会连接模式
    void OpenRendezvous(string adapter, string host, int port);

    virtual ~SrtCommon();
};

// SRT源
class SrtSource: public Source, public SrtCommon
{
    // 保存主机地址+端口号
    std::string hostport_copy;
public:

    SrtSource(std::string host, int port, const std::map<std::string,std::string>& par);
    SrtSource()
    {
        // Do nothing - create just to prepare for use
    }

    int Read(size_t chunk, MediaPacket& pkt, ostream& out_stats = cout) override;

    /*
       In this form this isn't needed.
       Unblock if any extra settings have to be made.
    virtual int ConfigurePre(UDTSOCKET sock) override
    {
        int result = SrtCommon::ConfigurePre(sock);
        if ( result == -1 )
            return result;
        return 0;
    }
    */

    bool IsOpen() override { return IsUsable(); }
    bool End() override { return IsBroken(); }

    SRTSOCKET GetSRTSocket() const override
    { 
        SRTSOCKET socket = SrtCommon::Socket();
        if (socket == SRT_INVALID_SOCK)
            socket = SrtCommon::Listener();
        return socket;
    }

    bool AcceptNewClient() override { return SrtCommon::AcceptNewClient(); }
};

class SrtTarget: public Target, public SrtCommon
{
public:

    SrtTarget(std::string host, int port, const std::map<std::string,std::string>& par)
    {
        Init(host, port, par, true);
    }

    SrtTarget() {}

    int ConfigurePre(SRTSOCKET sock) override;
    int Write(const char* data, size_t size, int64_t src_time, ostream &out_stats = cout) override;
    bool IsOpen() override { return IsUsable(); }
    bool Broken() override { return IsBroken(); }

    size_t Still() override
    {
        size_t bytes;
        int st = srt_getsndbuffer(m_sock, nullptr, &bytes);
        if (st == -1)
            return 0;
        return bytes;
    }

    SRTSOCKET GetSRTSocket() const override
    { 
        SRTSOCKET socket = SrtCommon::Socket();
        if (socket == SRT_INVALID_SOCK)
            socket = SrtCommon::Listener();
        return socket;
    }
    bool AcceptNewClient() override { return SrtCommon::AcceptNewClient(); }
};


// This class is used when we don't know yet whether the given URI
// designates an effective listener or caller. So we create it, initialize,
// then we know what mode we'll be using.
//
// When caller, then we will do connect() using this object, then clone out
// a new object - of a direction specific class - which will steal the socket
// from this one and then roll the data. After this, this object is ready
// to connect again, and will create its own socket for that occasion, and
// the whole procedure repeats.
//
// When listener, then this object will be doing accept() and with every
// successful acceptation it will clone out a new object - of a direction
// specific class - which will steal just the connection socket from this
// object. This object will still live on and accept new connections and
// so on.
class SrtModel: public SrtCommon
{
public:
    bool is_caller = false;
    string m_host;
    int m_port = 0;

    SrtModel(string host, int port, map<string,string> par);
    void Establish(std::string& name);
};



#endif
