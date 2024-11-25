/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

// Just for formality. This file should be used 
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>
#include <stdexcept>
#include <iterator>
#include <map>
#include <srt.h>
#if !defined(_WIN32)
#include <sys/ioctl.h>
#else
#include <fcntl.h>
#include <io.h>
#endif
#if defined(SUNOS)
#include <sys/filio.h>
#endif

#include "netinet_any.h"
#include "apputil.hpp"
#include "socketoptions.hpp"
#include "uriparser.hpp"
#include "transmitmedia.hpp"
#include "srt_compat.h"
#include "verbose.hpp"

using namespace std;
using namespace srt;

// SRT状态是否输出到标准输出
bool g_stats_are_printed_to_stdout = false;
bool transmit_total_stats = false;
// 用于控制带宽报告频率
unsigned long transmit_bw_report = 0;
// 用于控制状态统计频率
unsigned long transmit_stats_report = 0;
// 传输时的数据块大小
unsigned long transmit_chunk_size = SRT_LIVE_MAX_PLSIZE;

class FileSource: public Source
{
    ifstream ifile;
    string filename_copy;
public:

    FileSource(const string& path): ifile(path, ios::in | ios::binary), filename_copy(path)
    {
        if ( !ifile )
            throw std::runtime_error(path + ": Can't open file for reading");
    }

    int Read(size_t chunk, MediaPacket& pkt, ostream & ignored SRT_ATR_UNUSED = cout) override
    {
        if (pkt.payload.size() < chunk)
            pkt.payload.resize(chunk);

        pkt.time = 0;
        ifile.read(pkt.payload.data(), chunk);
        size_t nread = ifile.gcount();
        if (nread < pkt.payload.size())
            pkt.payload.resize(nread);

        if (pkt.payload.empty())
        {
            return 0;
        }

        return (int) nread;
    }

    bool IsOpen() override { return bool(ifile); }
    bool End() override { return ifile.eof(); }
};

class FileTarget: public Target
{
    ofstream ofile;
public:

    FileTarget(const string& path): ofile(path, ios::out | ios::trunc | ios::binary) {}

    int Write(const char* data, size_t size, int64_t time SRT_ATR_UNUSED, ostream & ignored SRT_ATR_UNUSED = cout) override
    {
        ofile.write(data, size);
        return !(ofile.bad()) ? (int) size : 0;
    }

    bool IsOpen() override { return !!ofile; }
    bool Broken() override { return !ofile.good(); }
    //~FileTarget() { ofile.close(); }
    void Close() override { ofile.close(); }
};

template <class Iface> struct File;
template <> struct File<Source> { typedef FileSource type; };
template <> struct File<Target> { typedef FileTarget type; };

template <class Iface>
Iface* CreateFile(const string& name) { return new typename File<Iface>::type (name); }

shared_ptr<SrtStatsWriter> transmit_stats_writer;

// 初始化SRT通用参数: 连接模式/网络适配器/超时时间/出站端口...
void SrtCommon::InitParameters(string host, map<string,string> par)
{
    // Application-specific options: mode, blocking, timeout, adapter

    // 如果开启了详细日志输出，则输出SRT参数
    if (Verbose::on && !par.empty())
    {
        Verb() << "SRT parameters specified:\n";
        for (map<string,string>::iterator i = par.begin(); i != par.end(); ++i)
        {
            cerr << "\t" << i->first << " = '" << i->second << "'\n";
        }
    }

    // 解析URI中的bind参数,获取网络适配器配置
    if (par.count("bind"))
    {
        /*
            URI中包含bind参数，说明是一个网络流
                - 按网络地址类型的URI进行解析
        */
        string bindspec = par.at("bind");
        UriParser u (bindspec, UriParser::EXPECT_HOST);
        if ( u.scheme() != ""
                || u.path() != ""
                || !u.parameters().empty()
                || u.portno() == 0)
        {
            Error("Invalid syntax in 'bind' option");
        }

        // 获取网络适配器参数
        if (u.host() != "")
            par["adapter"] = u.host();
        // 获取端口号
        par["port"] = u.port();
        // 删除bind参数
        par.erase("bind");
    }

    // 网络适配器
    string adapter;
    if (par.count("adapter"))
    {
        adapter = par.at("adapter");
    }

    // 连接模式: Listener/Caller/Rendezvous
    m_mode = "default";
    if (par.count("mode"))
    {
        m_mode = par.at("mode");
    }
    // 确定SRT连接模式: Listener/Caller/Rendezvous
    SocketOption::Mode mode = SrtInterpretMode(m_mode, host, adapter);
    if (mode == SocketOption::FAILURE)
    {
        Error("Invalid mode");
    }

    // Fix the mode name after successful interpretation
    // 修正连接模式
    m_mode = SocketOption::mode_names[mode];

    par.erase("mode");

    // 发送/接收超时
    if (par.count("timeout"))
    {
        m_timeout = stoi(par.at("timeout"), 0, 0);
        par.erase("timeout");
    }

    // 网络适配器
    if (par.count("adapter"))
    {
        m_adapter = par.at("adapter");
        par.erase("adapter");
    }
    else if (m_mode == "listener")
    {
        // For listener mode, adapter is taken from host,
        // if 'adapter' parameter is not given
        m_adapter = host;
    }

    // 是否使用基于时间戳的数据包传递模式，默认开启; 使用如下方式可以设置为关闭: 
    // srt://host:port?tsbpd=false
    // srt://host:port?tsbpd=off
    // srt://host:port?tsbpd=on
    // srt://host:port?tsbpd=0
    if (par.count("tsbpd") && false_names.count(par.at("tsbpd")))
    {
        m_tsbpdmode = false;
    }

    // 出站端口
    if (par.count("port"))
    {
        m_outgoing_port = stoi(par.at("port"), 0, 0);
        par.erase("port");
    }

    // That's kinda clumsy, but it must rely on the defaults.
    // Default mode is live, so check if the file mode was enforced
    if ((par.count("transtype") == 0 || par["transtype"] != "file")
        && transmit_chunk_size > SRT_LIVE_DEF_PLSIZE)
    {
        if (transmit_chunk_size > SRT_LIVE_MAX_PLSIZE)
            throw std::runtime_error("Chunk size in live mode exceeds 1456 bytes; this is not supported");

        par["payloadsize"] = Sprint(transmit_chunk_size);
    }

    // Assign the others here.
    m_options = par;
}

// SRT listener: 创建一个SRTSOCKET，并开始监听..
void SrtCommon::PrepareListener(string host, int port, int backlog)
{
    // 创建一个SRT套接字
    m_bindsock = srt_create_socket();
    if ( m_bindsock == SRT_ERROR )
        Error("srt_create_socket");

    // 建立SRT连接前需要设置的SRTSOCKET参数:TSBPD模式/同步接收模式/连接模式/网络适配器设置/延迟关闭...
    int stat = ConfigurePre(m_bindsock);
    if ( stat == SRT_ERROR )
        Error("ConfigurePre");

    // 创建监听地址
    sockaddr_any sa = CreateAddr(host, port);
    sockaddr* psa = sa.get();
    Verb() << "transmitmedia.cpp->SrtCommon::PrepareListener Binding a server on " << host << ":" << port << " ...";

    // bind
    stat = srt_bind(m_bindsock, psa, sizeof sa);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_bindsock);
        Error("srt_bind");
    }

    Verb() << "transmitmedia.cpp->SrtCommon::PrepareListener listen...";

    // listen
    stat = srt_listen(m_bindsock, backlog);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_bindsock);
        Error("srt_listen");
    }
}

void SrtCommon::StealFrom(SrtCommon& src)
{
    // This is used when SrtCommon class designates a listener
    // object that is doing Accept in appropriate direction class.
    // The new object should get the accepted socket.
    m_output_direction = src.m_output_direction;
    m_timeout = src.m_timeout;
    m_tsbpdmode = src.m_tsbpdmode;
    m_options = src.m_options;
    m_bindsock = SRT_INVALID_SOCK; // no listener
    m_sock = src.m_sock;
    src.m_sock = SRT_INVALID_SOCK; // STEALING
}

// 接受一个新的客户端连接
bool SrtCommon::AcceptNewClient()
{
    sockaddr_any scl;
    Verb() << "transmitmedia.cpp->SrtCommon::AcceptNewClient accept... ";

    // 接受一个新的客户端连接
    m_sock = srt_accept(m_bindsock, scl.get(), &scl.len);
    if ( m_sock == SRT_INVALID_SOCK )
    {
        srt_close(m_bindsock);
        m_bindsock = SRT_INVALID_SOCK;
        Error("srt_accept");
    }

    // we do one client connection at a time,
    // so close the listener.

    // 每次只接受一个连接，因此关闭监听套接字
    srt_close(m_bindsock);
    m_bindsock = SRT_INVALID_SOCK;

    Verb() << "transmitmedia.cpp->SrtCommon::AcceptNewClient connected.";

    // ConfigurePre is done on bindsock, so any possible Pre flags
    // are DERIVED by sock. ConfigurePost is done exclusively on sock.

    // 建立SRT连接后需要配置的SRTSOCKET选项: 异步模式/超时时间...
    int stat = ConfigurePost(m_sock);
    if ( stat == SRT_ERROR )
        Error("ConfigurePost");

    return true;
}

// SRT源或目标初始化:创建一个listener或caller
void SrtCommon::Init(string host, int port, map<string,string> par, bool dir_output)
{
    // 是否是输出流
    m_output_direction = dir_output;
    // 初始化SRT通用参数: 连接模式/网络适配器/超时时间/出站端口...
    InitParameters(host, par);

    Verb() << "transmitmedia.cpp->SrtCommon::Init Opening SRT " << (dir_output ? "target" : "source") << " " << m_mode
        << " on " << host << ":" << port;

    /* 根据连接模式，打开客户端或服务器 */

    // client: 创建一个SRT caller, 并连接到SRT服务器
    if ( m_mode == "caller" )
        OpenClient(host, port);
    // server: 创建一个SRT listener, 开始监听,等待客户端来拉流
    else if ( m_mode == "listener" )
        OpenServer(m_adapter, port);
    // rendezvous: 交会连接模式，绑定本地地址，和对端建立连接
    else if ( m_mode == "rendezvous" )
        OpenRendezvous(m_adapter, host, port);
    else
    {
        throw std::invalid_argument("Invalid 'mode'. Use 'client' or 'server'");
    }
}

// 建立SRT连接后，需要配置的SRTSOCKET参数: 异步模式/超时时间...
int SrtCommon::ConfigurePost(SRTSOCKET sock)
{
    bool no = false;
    int result = 0;

    // 输出流: 禁用同步发送模式，即当发送缓冲区中没有空间时，send()不会阻塞
    if ( m_output_direction )
    {
        result = srt_setsockopt(sock, 0, SRTO_SNDSYN, &no, sizeof no);
        if ( result == -1 )
            return result;

        // 异步发送模式下,send()的超时时间, 默认0; 即当发送缓冲区中没有空间时，立即返回
        if ( m_timeout )
            return srt_setsockopt(sock, 0, SRTO_SNDTIMEO, &m_timeout, sizeof m_timeout);
    }
    // 输入流: 禁用同步接收模式，即当接收缓冲区中没有数据时，recv()不会阻塞
    else
    {
        result = srt_setsockopt(sock, 0, SRTO_RCVSYN, &no, sizeof no);
        if ( result == -1 )
            return result;

        // 异步接收模式下,recv()的超时时间, 默认0; 即当接收缓冲区中没有数据时，立即返回
        if ( m_timeout )
            return srt_setsockopt(sock, 0, SRTO_RCVTIMEO, &m_timeout, sizeof m_timeout);
    }

    // 设置所有用户配置的SRT套接字参数
    SrtConfigurePost(sock, m_options);

    // 用户没有配置的参数，使用默认配置
    for (const auto &o: srt_options)
    {
        if ( o.binding == SocketOption::POST && m_options.count(o.name) )
        {
            string value = m_options.at(o.name);
            bool ok = o.apply<SocketOption::SRT>(sock, value);
            if ( !ok )
                Verb() << "transmitmedia.cpp->SrtCommon::ConfigurePost WARNING: failed to set '" << o.name << "' (post, "
                    << (m_output_direction? "target":"source") << ") to "
                    << value;
            else
                Verb() << "transmitmedia.cpp->SrtCommon::ConfigurePost NOTE: SRT/post::" << o.name << "=" << value;
        }
    }

    return 0;
}

// 建立SRT连接前，配置SRT套接字: TSBPD模式/同步接收模式/连接模式/网络适配器设置/延迟关闭...
int SrtCommon::ConfigurePre(SRTSOCKET sock)
{
    int result = 0;

    bool no = false;
    // 是否使用基于时间戳的数据包传递模式
    if ( !m_tsbpdmode )
    {
        result = srt_setsockopt(sock, 0, SRTO_TSBPDMODE, &no, sizeof no);
        if ( result == -1 )
            return result;
    }

    // 设置同步接收，即阻塞接收，默认使用异步接收模式
    result = srt_setsockopt(sock, 0, SRTO_RCVSYN, &no, sizeof no);
    if ( result == -1 )
        return result;


    // host is only checked for emptiness and depending on that the connection mode is selected.
    // Here we are not exactly interested with that information.
    vector<string> failures;

    // NOTE: here host = "", so the 'connmode' will be returned as LISTENER always,
    // but it doesn't matter here. We don't use 'connmode' for anything else than
    // checking for failures.

    // 配置SRT套接字: 连接模式/网络适配器设置/延迟关闭设置...
    SocketOption::Mode conmode = SrtConfigurePre(sock, "",  m_options, &failures);

    // 检查SRT套接字配置是否成功
    if ( conmode == SocketOption::FAILURE )
    {
        if ( Verbose::on )
        {
            cerr << "transmitmedia.cpp->SrtCommon::ConfigurePre WARNING: failed to set options: ";
            copy(failures.begin(), failures.end(), ostream_iterator<string>(cerr, ", "));
            cerr << endl;
        }

        return SRT_ERROR;
    }

    return 0;
}

// 设置网络适配器，绑定SRT套接字到指定地址
void SrtCommon::SetupAdapter(const string& host, int port)
{
    sockaddr_any localsa = CreateAddr(host, port);
    sockaddr* psa = localsa.get();
    int stat = srt_bind(m_sock, psa, sizeof localsa);
    if ( stat == SRT_ERROR )
        Error("srt_bind");
}

// 开启SRT客户端
void SrtCommon::OpenClient(string host, int port)
{
    // 开启客户端前的准备工作, 创建并设置SRTSOCKET选项
    PrepareClient();

    // 如果指定了输出端口或网络适配器，则将SRT套接字绑定到指定地址
    if (m_outgoing_port || m_adapter != "")
    {
        SetupAdapter(m_adapter, m_outgoing_port);
    }

    // 和SRT服务器建立连接
    ConnectClient(host, port);
}

// 开启客户端前的准备工作, 创建并设置SRTSOCKET选项
void SrtCommon::PrepareClient()
{
    // 创建一个SRT套接字
    m_sock = srt_create_socket();
    if ( m_sock == SRT_ERROR )
        Error("srt_create_socket");

    // 配置SRT套接字: TSBPD模式/同步接收模式/连接模式/网络适配器设置/延迟关闭...
    int stat = ConfigurePre(m_sock);
    if ( stat == SRT_ERROR )
        Error("ConfigurePre");
}

// 和SRT服务器建立连接
void SrtCommon::ConnectClient(string host, int port)
{
    // 根据参数创建地址
    sockaddr_any sa = CreateAddr(host, port);
    sockaddr* psa = sa.get();

    Verb() << "transmitmedia.cpp->SrtCommon::ConnectClient Connecting to " << host << ":" << port;

    // 建立SRT连接
    int stat = srt_connect(m_sock, psa, sizeof sa);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_sock);
        Error("srt_connect");
    }

    // 建立SRT连接后需要配置的SRTSOCKET选项
    stat = ConfigurePost(m_sock);
    if ( stat == SRT_ERROR )
        Error("ConfigurePost");
}

void SrtCommon::Error(string src)
{
    int errnov = 0;
    int result = srt_getlasterror(&errnov);
    string message = srt_getlasterror_str();
    Verb() << "\nERROR #" << result << "." << errnov << ": " << message;

    throw TransmissionError("error: " + src + ": " + message);
}

// 开启交会连接模式
void SrtCommon::OpenRendezvous(string adapter, string host, int port)
{
    // 创建一个SRT套接字
    m_sock = srt_create_socket();
    if ( m_sock == SRT_ERROR )
        Error("srt_create_socket");

    // 设置交会连接模式
    bool yes = true;
    srt_setsockopt(m_sock, 0, SRTO_RENDEZVOUS, &yes, sizeof yes);

    // 建立SRT连接前需要设置的SRTSOCKET参数: TSBPD模式/同步接收模式/连接模式/网络适配器设置/延迟关闭...
    int stat = ConfigurePre(m_sock);
    if ( stat == SRT_ERROR )
        Error("ConfigurePre");

    // 对端地址
    sockaddr_any sa = CreateAddr(host, port);
    if (sa.family() == AF_UNSPEC)
    {
        Error("OpenRendezvous: invalid target host specification: " + host);
    }

    // 出站端口
    const int outport = m_outgoing_port ? m_outgoing_port : port;

    // 本地地址
    sockaddr_any localsa = CreateAddr(adapter, outport, sa.family());

    Verb() << "transmitmedia.cpp->SrtCommon::OpenRendezvous Binding a server on " << adapter << ":" << outport;

    // 交会连接模式下，要求两端都必须要绑定地址
    stat = srt_bind(m_sock, localsa.get(), sizeof localsa);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_sock);
        Error("srt_bind");
    }

    Verb() << "transmitmedia.cpp->SrtCommon::OpenRendezvous Connecting to " << host << ":" << port;

    // 连接对端
    stat = srt_connect(m_sock, sa.get(), sizeof sa);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_sock);
        Error("srt_connect");
    }

    // 建立SRT连接后需要配置的SRTSOCKET选项:主要是将发送接收改为异步模式
    stat = ConfigurePost(m_sock);
    if ( stat == SRT_ERROR )
        Error("ConfigurePost");
}

void SrtCommon::Close()
{
    Verb() << "SrtCommon: DESTROYING CONNECTION, closing sockets (rt%" << m_sock << " ls%" << m_bindsock << ")...";

    if ( m_sock != SRT_INVALID_SOCK )
    {
        srt_close(m_sock);
        m_sock = SRT_INVALID_SOCK;
    }

    if ( m_bindsock != SRT_INVALID_SOCK )
    {
        srt_close(m_bindsock);
        m_bindsock = SRT_INVALID_SOCK ;
    }

    Verb() << "SrtCommon: ... done.";
}

SrtCommon::~SrtCommon()
{
    Close();
}

// SRT源初始化
SrtSource::SrtSource(string host, int port, const map<string,string>& par)
{
    // SRT源初始化,false表示是一个输入流，即接收数据
    Init(host, port, par, false);

    // 保存主机地址+端口号
    ostringstream os;
    os << host << ":" << port;
    hostport_copy = os.str();
}

// 从SRT流中读数据，读取固定大小的数据保存到pkt中，在此过程中会进行带宽和状态统计
int SrtSource::Read(size_t chunk, MediaPacket& pkt, ostream &out_stats)
{
    // 用于控制带宽报告和状态统计的频率
    static unsigned long counter = 1;

    // 确保有足够的空间来保存一个包
    if (pkt.payload.size() < chunk)
        pkt.payload.resize(chunk);

    // SRT控制报文
    SRT_MSGCTRL ctrl;
    const int stat = srt_recvmsg2(m_sock, pkt.payload.data(), (int) chunk, &ctrl);
    if (stat <= 0)
    {
        pkt.payload.clear();
        return stat;
    }

    pkt.time = ctrl.srctime;

    // 调整缓冲区大小为实际读取到的数据大小，优化内存使用
    chunk = size_t(stat);
    if (chunk < pkt.payload.size())
        pkt.payload.resize(chunk);

    // 带宽报告频率
    const bool need_bw_report = transmit_bw_report && (counter % transmit_bw_report) == transmit_bw_report - 1;
    // 状态统计频率
    const bool need_stats_report = transmit_stats_report && (counter % transmit_stats_report) == transmit_stats_report - 1;

    // SRT性能探测
    if (need_bw_report || need_stats_report)
    {
        CBytePerfMon perf;
        srt_bstats(m_sock, &perf, need_stats_report && !transmit_total_stats);
        if (transmit_stats_writer != nullptr) 
        {
            if (need_bw_report)
                cerr << transmit_stats_writer->WriteBandwidth(perf.mbpsBandwidth) << std::flush;
            if (need_stats_report)
                out_stats << transmit_stats_writer->WriteStats(m_sock, perf) << std::flush;
        }
    }
    ++counter;
    return stat;
}

// SRT目的建立连接前的配置: TSBPD模式/同步接收模式/连接模式/网络适配器设置/延迟关闭...
int SrtTarget::ConfigurePre(SRTSOCKET sock)
{
    int result = SrtCommon::ConfigurePre(sock);
    if ( result == -1 )
        return result;

    int yes = 1;
    // This is for the HSv4 compatibility; if both parties are HSv5
    // (min. version 1.2.1), then this setting simply does nothing.
    // In HSv4 this setting is obligatory; otherwise the SRT handshake
    // extension will not be done at all.
    // 发送者模式，用于加密和TSBPD握手
    result = srt_setsockopt(sock, 0, SRTO_SENDER, &yes, sizeof yes);
    if ( result == -1 )
        return result;

    return 0;
}

// 向SRT目标写数据，在此过程中会进行带宽和状态统计
int SrtTarget::Write(const char* data, size_t size, int64_t src_time, ostream &out_stats)
{
    // 用于控制带宽报告和状态统计的频率
    static unsigned long counter = 1;

    // SRT控制报文
    SRT_MSGCTRL ctrl = srt_msgctrl_default;
    ctrl.srctime = src_time;

    // 发送数据
    int stat = srt_sendmsg2(m_sock, data, (int) size, &ctrl);
    if (stat == SRT_ERROR)
    {
        return stat;
    }

    // 带宽报告频率
    const bool need_bw_report = transmit_bw_report && (counter % transmit_bw_report) == transmit_bw_report - 1;
    // 状态统计频率
    const bool need_stats_report = transmit_stats_report && (counter % transmit_stats_report) == transmit_stats_report - 1;

    // SRT性能探测
    if (need_bw_report || need_stats_report)
    {
        CBytePerfMon perf;
        srt_bstats(m_sock, &perf, need_stats_report && !transmit_total_stats);
        if (transmit_stats_writer != nullptr)
        {
            if (need_bw_report)
                cerr << transmit_stats_writer->WriteBandwidth(perf.mbpsBandwidth) << std::flush;
            if (need_stats_report)
                out_stats << transmit_stats_writer->WriteStats(m_sock, perf) << std::flush;
        }
    }
    ++counter;
    return stat;
}


SrtModel::SrtModel(string host, int port, map<string,string> par)
{
    InitParameters(host, par);
    if (m_mode == "caller")
        is_caller = true;
    else if (m_mode != "listener")
        throw std::invalid_argument("Only caller and listener modes supported");

    m_host = host;
    m_port = port;
}

void SrtModel::Establish(std::string& w_name)
{
    // This does connect or accept.
    // When this returned true, the caller should create
    // a new SrtSource or SrtTaget then call StealFrom(*this) on it.

    // If this is a connector and the peer doesn't have a corresponding
    // medium, it should send back a single byte with value 0. This means
    // that agent should stop connecting.

    if (is_caller)
    {
        // Establish a connection

        PrepareClient();

        if (w_name != "")
        {
            Verb() << "Connect with requesting stream [" << w_name << "]";
            srt::setstreamid(m_sock, w_name);
        }
        else
        {
            Verb() << "NO STREAM ID for SRT connection";
        }

        if (m_outgoing_port)
        {
            Verb() << "Setting outgoing port: " << m_outgoing_port;
            SetupAdapter("", m_outgoing_port);
        }

        ConnectClient(m_host, m_port);

        if (m_outgoing_port == 0)
        {
            // Must rely on a randomly selected one. Extract the port
            // so that it will be reused next time.
            sockaddr_any s(AF_INET);
            int namelen = s.size();
            if ( srt_getsockname(Socket(), s.get(), &namelen) == SRT_ERROR )
            {
                Error("srt_getsockname");
            }

            m_outgoing_port = s.hport();
            Verb() << "Extracted outgoing port: " << m_outgoing_port;
        }
    }
    else
    {
        // Listener - get a socket by accepting.
        // Check if the listener is already created first
        if (Listener() == SRT_INVALID_SOCK)
        {
            Verb() << "Setting up listener: port=" << m_port << " backlog=5";
            PrepareListener(m_adapter, m_port, 5);
        }

        Verb() << "Accepting a client...";
        AcceptNewClient();
        // This rewrites m_sock with a new SRT socket ("accepted" socket)
        w_name = srt::getstreamid(m_sock);
        Verb() << "... GOT CLIENT for stream [" << w_name << "]";
    }
}

// 定义一个模板结构体struct Srt
template <class Iface> struct Srt;
// 模板特化 - 将struct Srt特化为Source类型, 结构体中定义的type类型为SrtSource
template <> struct Srt<Source> { typedef SrtSource type; };
// 模板特化 - 将struct Srt特化为Target类型, 结构体中定义的type类型为SrtTarget
template <> struct Srt<Target> { typedef SrtTarget type; };

// 创建一个SRT流对象
template <class Iface>
Iface* CreateSrt(const string& host, int port, const map<string,string>& par) { return new typename Srt<Iface>::type (host, port, par); }

class ConsoleSource: public Source
{
public:

    ConsoleSource()
    {
#ifdef _WIN32
        // The default stdin mode on windows is text.
        // We have to set it to the binary mode
        _setmode(_fileno(stdin), _O_BINARY);
#endif
    }

    int Read(size_t chunk, MediaPacket& pkt, ostream & ignored SRT_ATR_UNUSED = cout) override
    {
        if (pkt.payload.size() < chunk)
            pkt.payload.resize(chunk);

        bool st = cin.read(pkt.payload.data(), chunk).good();
        chunk = cin.gcount();
        if (chunk == 0 || !st)
        {
            pkt.payload.clear();
            return 0;
        }

        // Save this time to potentially use it for SRT target.
        pkt.time = srt_time_now();
        if (chunk < pkt.payload.size())
            pkt.payload.resize(chunk);

        return (int) chunk;
    }

    bool IsOpen() override { return cin.good(); }
    bool End() override { return cin.eof(); }
    int GetSysSocket() const override { return 0; };
};

class ConsoleTarget: public Target
{
public:

    ConsoleTarget()
    {
#ifdef _WIN32
        // The default stdout mode on windows is text.
        // We have to set it to the binary mode
        _setmode(_fileno(stdout), _O_BINARY);
#endif
    }

    virtual ~ConsoleTarget()
    {
        cout.flush();
    }

    int Write(const char* data, size_t len, int64_t src_time SRT_ATR_UNUSED, ostream & ignored SRT_ATR_UNUSED = cout) override
    {
        cout.write(data, len);
        return (int) len;
    }

    bool IsOpen() override { return cout.good(); }
    bool Broken() override { return cout.eof(); }
    int GetSysSocket() const override { return 0; };
};

template <class Iface> struct Console;
template <> struct Console<Source> { typedef ConsoleSource type; };
template <> struct Console<Target> { typedef ConsoleTarget type; };

template <class Iface>
Iface* CreateConsole() { return new typename Console<Iface>::type (); }


// More options can be added in future.
SocketOption udp_options [] {
    { "iptos", IPPROTO_IP, IP_TOS, SocketOption::PRE, SocketOption::INT, nullptr },
    // IP_TTL and IP_MULTICAST_TTL are handled separately by a common option, "ttl".
    { "mcloop", IPPROTO_IP, IP_MULTICAST_LOOP, SocketOption::PRE, SocketOption::INT, nullptr },
    { "sndbuf", SOL_SOCKET, SO_SNDBUF, SocketOption::PRE, SocketOption::INT, nullptr},
    { "rcvbuf", SOL_SOCKET, SO_RCVBUF, SocketOption::PRE, SocketOption::INT, nullptr}
};

// 判断是否为组播地址：对于IPv4，组播地址范围为224.0.0.0到239.255.255.255
static inline bool IsMulticast(in_addr adr)
{
    unsigned char* abytes = (unsigned char*)&adr.s_addr;
    unsigned char c = abytes[0];
    return c >= 224 && c <= 239;
}

/*
    UDP流的通用类
        - 创建一个UDP套接字，并设置为非阻塞模式
*/
class UdpCommon
{
protected:
    // SYSSOCKET
    int m_sock = -1;
    // 本地地址，用于绑定
    sockaddr_any sadr;
    // 网络适配器
    string adapter;
    // 选项
    map<string, string> m_options;

    // 创建一个UDP套接字，并设置为非阻塞模式
    void Setup(string host, int port, map<string,string> attr)
    {
        // 创建一个UDP套接字
        m_sock = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (m_sock == -1)
            Error(SysError(), "UdpCommon::Setup: socket");

        // 地址复用
        int yes = 1;
        ::setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof yes);

        // set non-blocking mode
        // 设置套接字为非阻塞模式
#if defined(_WIN32)
        unsigned long ulyes = 1;
        if (ioctlsocket(m_sock, FIONBIO, &ulyes) == SOCKET_ERROR)
#else
        if (ioctl(m_sock, FIONBIO, (const char *)&yes) < 0)
#endif
        {
            Error(SysError(), "UdpCommon::Setup: ioctl FIONBIO");
        }

        // 地址
        sadr = CreateAddr(host, port);

        // 是否为组播
        bool is_multicast = false;

        // 设置了组播选项
        if (attr.count("multicast"))
        {
            // XXX: Here provide support for IPv6 multicast #1479
            if (sadr.family() != AF_INET)
            {
                throw std::runtime_error("UdpCommon: Multicast on IPv6 is not yet supported");
            }

            if (!IsMulticast(sadr.sin.sin_addr))
            {
                throw std::runtime_error("UdpCommon: requested multicast for a non-multicast-type IP address");
            }
            is_multicast = true;
        }
        // 判断是否是一个组播地址
        else if (sadr.family() == AF_INET && IsMulticast(sadr.sin.sin_addr))
        {
            is_multicast = true;
        }

        // 开启组播
        if (is_multicast)
        {
            ip_mreq mreq;
            sockaddr_any maddr (AF_INET);
            int opt_name;
            void* mreq_arg_ptr;
            socklen_t mreq_arg_size;

            adapter = attr.count("adapter") ? attr.at("adapter") : string();
            if ( adapter == "" )
            {
                Verb() << "Multicast: home address: INADDR_ANY:" << port;
                maddr.sin.sin_family = AF_INET;
                maddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
                maddr.sin.sin_port = htons(port); // necessary for temporary use
            }
            else
            {
                Verb() << "Multicast: home address: " << adapter << ":" << port;
                maddr = CreateAddr(adapter, port);
            }

            if (attr.count("source"))
            {
#ifdef IP_ADD_SOURCE_MEMBERSHIP
                ip_mreq_source mreq_ssm;
                /* this is an ssm.  we need to use the right struct and opt */
                opt_name = IP_ADD_SOURCE_MEMBERSHIP;
                mreq_ssm.imr_multiaddr.s_addr = sadr.sin.sin_addr.s_addr;
                mreq_ssm.imr_interface.s_addr = maddr.sin.sin_addr.s_addr;
                inet_pton(AF_INET, attr.at("source").c_str(), &mreq_ssm.imr_sourceaddr);
                mreq_arg_size = sizeof(mreq_ssm);
                mreq_arg_ptr = &mreq_ssm;
#else
                throw std::runtime_error("UdpCommon: source-filter multicast not supported by OS");
#endif
            }
            else
            {
                opt_name = IP_ADD_MEMBERSHIP;
                mreq.imr_multiaddr.s_addr = sadr.sin.sin_addr.s_addr;
                mreq.imr_interface.s_addr = maddr.sin.sin_addr.s_addr;
                mreq_arg_size = sizeof(mreq);
                mreq_arg_ptr = &mreq;
            }

#ifdef _WIN32
            const char* mreq_arg = (const char*)mreq_arg_ptr;
            const auto status_error = SOCKET_ERROR;
#else
            const void* mreq_arg = mreq_arg_ptr;
            const auto status_error = -1;
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
            // On Windows it somehow doesn't work when bind()
            // is called with multicast address. Write the address
            // that designates the network device here.
            // Also, sets port sharing when working with multicast
            sadr = maddr;
            int reuse = 1;
            int shareAddrRes = setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
            if (shareAddrRes == status_error)
            {
                throw runtime_error("marking socket for shared use failed");
            }
            Verb() << "Multicast(Windows): will bind to home address";
#else
            Verb() << "Multicast(POSIX): will bind to IGMP address: " << host;
#endif
            int res = setsockopt(m_sock, IPPROTO_IP, opt_name, mreq_arg, mreq_arg_size);

            if ( res == status_error )
            {
                Error(errno, "adding to multicast membership failed");
            }

            attr.erase("multicast");
            attr.erase("adapter");
        }

        // The "ttl" options is handled separately, it maps to both IP_TTL
        // and IP_MULTICAST_TTL so that TTL setting works for both uni- and multicast.
        // 设置ttl选项
        if (attr.count("ttl"))
        {
            int ttl = stoi(attr.at("ttl"));
            int res = setsockopt(m_sock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof ttl);
            if (res == -1)
                Verb() << "WARNING: failed to set 'ttl' (IP_TTL) to " << ttl;
            res = setsockopt(m_sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&ttl, sizeof ttl);
            if (res == -1)
                Verb() << "WARNING: failed to set 'ttl' (IP_MULTICAST_TTL) to " << ttl;

            attr.erase("ttl");
        }

        m_options = attr;

        // 设置其它选项
        for (auto o: udp_options)
        {
            // Ignore "binding" - for UDP there are no post options.
            if ( m_options.count(o.name) )
            {
                string value = m_options.at(o.name);
                bool ok = o.apply<SocketOption::SYSTEM>(m_sock, value);
                if ( !ok )
                    Verb() << "WARNING: failed to set '" << o.name << "' to " << value;
            }
        }
    }

    void Error(int err, string src)
    {
        char buf[512];
        string message = SysStrError(err, buf, 512u);

        cerr << "\nERROR #" << err << ": " << message << endl;

        throw TransmissionError("error: " + src + ": " + message);
    }

    ~UdpCommon()
    {
#ifdef _WIN32
        if (m_sock != -1)
        {
           shutdown(m_sock, SD_BOTH);
           closesocket(m_sock);
           m_sock = -1;
        }
#else
        close(m_sock);
#endif
    }
};

// 源是UDP类型
class UdpSource: public Source, public UdpCommon
{
protected:
    // 是否读到UDP流的末尾，即UDP流是否结束
    bool eof = true;
public:

    // 构造函数 - 
    UdpSource(string host, int port, const map<string,string>& attr)
    {
        // 创建一个UDP套接字，并设置为非阻塞模式
        Setup(host, port, attr);
        // 地址绑定
        int stat = ::bind(m_sock, sadr.get(), sadr.size());
        if ( stat == -1 )
            Error(SysError(), "Binding address for UDP");
        eof = false;

        cout << "transmitmedia.cpp->UdpSource UDP Socket bind at " << host << ":" << port << endl;
    }

    // 从UDP流中读取指定大小的数据
    int Read(size_t chunk, MediaPacket& pkt, ostream & ignored SRT_ATR_UNUSED = cout) override
    {
        // 确保媒体数据包的缓冲区有足够空间容纳一个chunk大小的数据
        if (pkt.payload.size() < chunk)
            pkt.payload.resize(chunk);

        // 保存对端地址
        sockaddr_any sa(sadr.family());
        socklen_t si = sa.size();
        // 从UDP套接字中读取数据
        int stat = recvfrom(m_sock, pkt.payload.data(), (int) chunk, 0, sa.get(), &si);
        if (stat < 1)
        {
            if (SysError() != EWOULDBLOCK)
                eof = true;
            pkt.payload.clear();
            return stat;
        }
        sa.len = si;

        // Save this time to potentially use it for SRT target.
        // 保存从UDP中接收到数据时的时间戳
        pkt.time = srt_time_now();
        // 真实读取到的数据大小
        chunk = size_t(stat);
        // 调整pkt负载的大小，优化内存使用
        if (chunk < pkt.payload.size())
            pkt.payload.resize(chunk);

        return stat;
    }

    // 判断UDP套接字是否已创建
    bool IsOpen() override { return m_sock != -1; }
    // 判断UDP流是否结束
    bool End() override { return eof; }

    // 获取UDP套接字
    int GetSysSocket() const override { return m_sock; };
};

class UdpTarget: public Target, public UdpCommon
{
public:
    UdpTarget(string host, int port, const map<string,string>& attr )
    {
        if (host.empty())
            cerr << "\nWARN Host for UDP target is not provided. Will send to localhost:" << port << ".\n";

        Setup(host, port, attr);
        if (adapter != "")
        {
            sockaddr_any maddr = CreateAddr(adapter, 0);
            if (maddr.family() != AF_INET)
            {
                Error(0, "UDP/target: IPv6 multicast not supported in the application");
            }

            in_addr addr = maddr.sin.sin_addr;

            int res = setsockopt(m_sock, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<const char*>(&addr), sizeof(addr));
            if (res == -1)
            {
                Error(SysError(), "setsockopt/IP_MULTICAST_IF: " + adapter);
            }
        }

    }

    int Write(const char* data, size_t len, int64_t src_time SRT_ATR_UNUSED,  ostream & ignored SRT_ATR_UNUSED = cout) override
    {
        int stat = sendto(m_sock, data, (int) len, 0, sadr.get(), sadr.size());
        if ( stat == -1 )
        {
            if ((false))
                Error(SysError(), "UDP Write/sendto");
            return stat;
        }
        return stat;
    }

    bool IsOpen() override { return m_sock != -1; }
    bool Broken() override { return false; }

    int GetSysSocket() const override { return m_sock; };
};

// 定义一个模板结构体struct Udp
template <class Iface> struct Udp;
// 模板特化 - 定义一个UdpSource类型; UdpSource == Udp<Source>::type;
template <> struct Udp<Source> { typedef UdpSource type; };
// 模板特化 - 定义一个UdpTarget类型; UdpTarget == Udp<Target>::type;
template <> struct Udp<Target> { typedef UdpTarget type; };

// 模板函数 - 根据传入的Iface类型，创建一个UdpSource或UdpTarget对象
template <class Iface>
Iface* CreateUdp(const string& host, int port, const map<string,string>& par) { return new typename Udp<Iface>::type (host, port, par); }

class RtpSource: public UdpSource
{
    // for now, make no effort to parse the header, just assume it is always
    // fixed length and either a user-configurable value, or twelve bytes.
    const int MINIMUM_RTP_HEADER_SIZE = 12;
    int bytes_to_skip = MINIMUM_RTP_HEADER_SIZE;
public:
    RtpSource(string host, int port, const map<string,string>& attr) :
        UdpSource { host, port, attr }
        {
            if (attr.count("rtpheadersize"))
            {
                const int header_size = stoi(attr.at("rtpheadersize"), 0, 0);
                if (header_size < MINIMUM_RTP_HEADER_SIZE)
                {
                    cerr << "Invalid RTP header size provided: " << header_size
                        << ", minimum allowed is " << MINIMUM_RTP_HEADER_SIZE
                        << endl;
                    throw invalid_argument("Invalid RTP header size");
                }
                bytes_to_skip = header_size;
            }
        }

    int Read(size_t chunk, MediaPacket& pkt, ostream & ignored SRT_ATR_UNUSED = cout) override
    {
        const int length = UdpSource::Read(chunk, pkt);

        if (length < 1 || !bytes_to_skip)
        {
            // something went wrong, or we're not skipping bytes for some
            // reason, just return the length read via the base method
            return length;
        }

        // we got some data and we're supposed to skip some of it
        // check there's enough bytes for our intended skip
        if (length < bytes_to_skip)
        {
            // something went wrong here
            cerr << "RTP packet too short (" << length
                << " bytes) to remove headers (needed "
                << bytes_to_skip << ")" << endl;
            throw std::runtime_error("Unexpected RTP packet length");
        }

        pkt.payload.erase(
            pkt.payload.begin(),
            pkt.payload.begin() + bytes_to_skip
        );

        return length - bytes_to_skip;
    }
};

class RtpTarget : public UdpTarget {
public:
    RtpTarget(string host, int port, const map<string,string>& attr ) :
        UdpTarget { host, port, attr } {}
};

template <class Iface> struct Rtp;
template <> struct Rtp<Source> { typedef RtpSource type; };
template <> struct Rtp<Target> { typedef RtpTarget type; };

template <class Iface>
Iface* CreateRtp(const string& host, int port, const map<string,string>& par) { return new typename Rtp<Iface>::type (host, port, par); }

// 判断是否是输出流
template<class Base>
inline bool IsOutput() { return false; }

// 判断是否是输入流
template<>
inline bool IsOutput<Target>() { return true; }

/*
    模板函数
        - 根据URI创建源或目标媒介
        - 这里这个extern不是必须的，为什么要加extern呢?
*/
template <class Base>
extern unique_ptr<Base> CreateMedium(const string& uri)
{
    unique_ptr<Base> ptr;

    // 解析URI
    UriParser u(uri);

    int iport = 0;
    // 不同的URI类型，创建不同的媒介
    switch ( u.type() )
    {
    default:
        break; // do nothing, return nullptr
    // 文件类型的URI
    case UriParser::FILE:
        // URT指向控制台
        if (u.host() == "con" || u.host() == "console")
        {
            if (IsOutput<Base>() && (
                (Verbose::on && Verbose::cverb == &cout)
                || g_stats_are_printed_to_stdout))
            {
                cerr << "ERROR: file://con with -v or -r or -s would result in mixing the data and text info.\n";
                cerr << "ERROR: HINT: you can stream through a FIFO (named pipe)\n";
                throw invalid_argument("incorrect parameter combination");
            }
            ptr.reset(CreateConsole<Base>());
        }
// Disable regular file support for the moment
#if 0
        else
            ptr.reset( CreateFile<Base>(u.path()));
#endif
        break;

    // URI是SRT类型
    case UriParser::SRT:
        cout << "transmitmedia.cpp->CreateMedium SRT " << endl;
        // 获取URI中的端口号
        iport = atoi(u.port().c_str());
        // 端口号必须大于等于1024,1024以下的是知名端口号，最好不要使用
        if ( iport < 1024 )
        {
            cerr << "Port value invalid: " << iport << " - must be >=1024\n";
            throw invalid_argument("Invalid port number");
        }
        // 创建一个SRT源或目标对象
        ptr.reset( CreateSrt<Base>(u.host(), iport, u.parameters()) );
        break;

    // URI是UDP类型，创建一个UdpSource或UdpTarget对象
    case UriParser::UDP:
        cout << "transmitmedia.cpp->CreateMedium UDP " << endl;
        // 获取URI中的端口号，禁止使用知名端口号
        iport = atoi(u.port().c_str());
        if ( iport < 1024 )
        {
            cerr << "Port value invalid: " << iport << " - must be >=1024\n";
            throw invalid_argument("Invalid port number");
        }
        ptr.reset( CreateUdp<Base>(u.host(), iport, u.parameters()) );
        break;

    // URI是RTP类型，
    case UriParser::RTP:
        // 如果是输出流，则报错; RTP协议不支持输出，只能作为输入源
        if (IsOutput<Base>())
        {
            cerr << "RTP not supported as an output\n";
            throw invalid_argument("Invalid output protocol: RTP");
        }
        // 禁止使用知名端口号
        iport = atoi(u.port().c_str());
        if ( iport < 1024 )
        {
            cerr << "Port value invalid: " << iport << " - must be >=1024\n";
            throw invalid_argument("Invalid port number");
        }
        ptr.reset( CreateRtp<Base>(u.host(), iport, u.parameters()) );
        break;
    }

    // 媒体对象创建成功后，保存URI信息
    if (ptr.get())
        ptr->uri = std::move(u);

    return ptr;
}

// 工厂方法-创建源媒体对象
std::unique_ptr<Source> Source::Create(const std::string& url)
{
    return CreateMedium<Source>(url);
}

// 工厂方法-创建目标媒体对象
std::unique_ptr<Target> Target::Create(const std::string& url)
{
    return CreateMedium<Target>(url);
}
