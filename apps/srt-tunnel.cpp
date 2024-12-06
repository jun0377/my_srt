// MSVS likes to complain about lots of standard C functions being unsafe.
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#include <io.h>
#endif

#include "platform_sys.h"

#define REQUIRE_CXX11 1

#include <cctype>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <deque>
#include <memory>
#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <cstring>
#include <csignal>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "srt_compat.h"
#include "apputil.hpp"  // CreateAddr
#include "uriparser.hpp"  // UriParser
#include "socketoptions.hpp"
#include "logsupport.hpp"
#include "transmitbase.hpp" // bytevector typedef to avoid collisions
#include "verbose.hpp"

// NOTE: This is without "haisrt/" because it uses an internal path
// to the library. Application using the "installed" library should
// use <srt/srt.h>
#include <srt.h>
#include <udt.h> // This TEMPORARILY contains extra C++-only SRT API.
#include <logging.h>
#include <api.h>
#include <utilities.h>

/*
# MAF contents for this file. Note that not every file from the support
# library is used, but to simplify the build definition it links against
# the whole srtsupport library.

SOURCES
srt-test-tunnel.cpp
testmedia.cpp
../apps/verbose.cpp
../apps/socketoptions.cpp
../apps/uriparser.cpp
../apps/logsupport.cpp

*/

using namespace std;
using namespace srt;

const srt_logging::LogFA SRT_LOGFA_APP = 10;
namespace srt_logging
{
Logger applog(SRT_LOGFA_APP, srt_logger_config, "TUNNELAPP");
}

using srt_logging::applog;

class Medium
{
    // 引用计数
    static int s_counter;
    // 每个媒体实例的标识ID
    int m_counter;
public:
    // 从媒体读取数据时的状态: 读数据/再次读数据/读到末尾/读数据错误
    enum ReadStatus
    {
        RD_DATA, RD_AGAIN, RD_EOF, RD_ERROR
    };

    /*
        两种模式:
            - listener模式 - 类似TCP Server
            - caller模式 - 类似TCP Client
    */
    enum Mode
    {
        LISTENER, CALLER
    };

protected:
    // URI解析器
    UriParser m_uri;
    // 数据块大小
    size_t m_chunk = 0;
    // 用户配置的选项
    map<string, string> m_options;
    // 模式: listener/caller
    Mode m_mode;

    // 是否作为listener
    bool m_listener = false;
    // 媒体是否已经打开
    bool m_open = false;
    // 是否已经读到了末尾
    bool m_eof = false;
    // 连接是否出现异常
    bool m_broken = false;

    std::mutex access; // For closing

    // 模板方法 - 创建一个用于接收连接的媒体实例
    template <class DerivedMedium, class SocketType>
    static Medium* CreateAcceptor(DerivedMedium* self, const sockaddr_any& sa, SocketType sock, size_t chunk)
    {
        cout << "srt-tunnel.cpp CreateAcceptor" << endl;

        // 接收媒体连接的本地地址
        string addr = sockaddr_any(sa.get(), sizeof sa).str();
        DerivedMedium* m = new DerivedMedium(UriParser(self->type() + string("://") + addr), chunk);
        m->m_socket = sock;
        return m;
    }

public:

    // 获取媒体URI
    string uri() { return m_uri.uri(); }
    // 获取媒体流ID
    string id()
    {
        std::ostringstream os;
        os << type() << m_counter;
        return os.str();
    }

    // 构造函数
    Medium(const UriParser& u, size_t ch): m_counter(s_counter++), m_uri(u), m_chunk(ch) {}
    Medium(): m_counter(s_counter++) {}

    // 获取媒体流的类型
    virtual const char* type() = 0;
    // 媒体流是否已经打开
    virtual bool IsOpen() = 0;
    // 
    virtual void CloseInternal() = 0;

    // 关闭媒体流时，设置相关标志位
    void CloseState()
    {
        m_open = false;
        m_broken = true;
    }

    // External API for this class that allows to close
    // the entity on request. The CloseInternal should
    // redirect to a type-specific function, the same that
    // should be also called in destructor.
    // 关闭媒体流
    void Close()
    {
        CloseState();
        CloseInternal();
    }
    // 媒体流是否已经结束
    virtual bool End() = 0;

    // 具体的读取数据方法
    virtual int ReadInternal(char* output, int size) = 0;
    virtual bool IsErrorAgain() = 0;

    // 从媒体流读数据
    ReadStatus Read(bytevector& output);
    // 向媒体流写数据
    virtual void Write(bytevector& portion) = 0;

    // 创建一个listener
    virtual void CreateListener() = 0;
    // 创建一个caller
    virtual void CreateCaller() = 0;
    // 接收连接
    virtual unique_ptr<Medium> Accept() = 0;
    // 连接对端
    virtual void Connect() = 0;

    // 根据URI创建一个SRT或TCP媒体流
    static std::unique_ptr<Medium> Create(const std::string& url, size_t chunk, Mode);

    // 连接是否出现异常
    virtual bool Broken() = 0;
    virtual size_t Still() { return 0; }

    // 读取到EOF时抛出的异常
    class ReadEOF: public std::runtime_error
    {
    public:
        ReadEOF(const std::string& fn): std::runtime_error( "EOF while reading file: " + fn )
        {
        }
    };

    // 传输错误时抛出的异常
    class TransmissionError: public std::runtime_error
    {
    public:
        TransmissionError(const std::string& fn): std::runtime_error( fn )
        {
        }
    };

    // 内部错误时抛出的异常
    static void Error(const string& text)
    {
        throw TransmissionError("ERROR (internal): " + text);
    }

    virtual ~Medium()
    {
        CloseState();
    }

protected:
    // 初始化模式: listener/caller
    void InitMode(Mode m)
    {
        m_mode = m;
        Init();

        // 创建listener
        if (m_mode == LISTENER)
        {
            CreateListener();
            m_listener = true;
        }
        // 创建caller
        else
        {
            CreateCaller();
        }

        m_open = true;
    }

    virtual void Init() {}

};

// 用于处理媒体传输，传输引擎
class Engine
{
	// 源和目的
    Medium* media[2];
	// 资源回收线程
    std::thread thr;
    class Tunnel* parent_tunnel;
    std::string nameid;

    int status = 0;

	// 媒体数据读取状态
    Medium::ReadStatus rdst = Medium::RD_ERROR;
    UDT::ERRORINFO srtx;

public:
	
	// 媒体传输方向
    enum Dir { DIR_IN, DIR_OUT };

	// 获取状态
    int stat() { return status; }

    Engine(Tunnel* p, Medium* m1, Medium* m2, const std::string& nid)
        :
#ifdef HAVE_FULL_CXX11
		// C++11的列表初始化语法初始化数组
        media {m1, m2},
#endif
        parent_tunnel(p), nameid(nid)
    {
#ifndef HAVE_FULL_CXX11
        // MSVC is not exactly C++11 compliant and complains around
        // initialization of an array.
        // Leaving this method of initialization for clarity and
        // possibly more preferred performance.
        media[0] = m1;
        media[1] = m2;
#endif
    }

	// 创建工作线程
    void Start()
    {
		Verb() << "START: " << media[DIR_IN]->uri() << " --> " << media[DIR_OUT]->uri();

		// 设置线程名称
		const std::string thrn = media[DIR_IN]->id() + ">" + media[DIR_OUT]->id();
        srt::ThreadName tn(thrn);

        thr = thread([this]() { Worker(); });
    }

    void Stop()
    {
        // If this thread is already stopped, don't stop.
        if (thr.joinable())
        {
            LOGP(applog.Debug, "Engine::Stop: Closing media:");
            // Close both media as a hanged up reading thread
            // will block joining.
            media[0]->Close();
            media[1]->Close();

            LOGP(applog.Debug, "Engine::Stop: media closed, joining engine thread:");
            if (thr.get_id() == std::this_thread::get_id())
            {
                // If this is this thread which called this, no need
                // to stop because this thread will exit by itself afterwards.
                // You must, however, detach yourself, or otherwise the thr's
                // destructor would kill the program.
                thr.detach();
                LOGP(applog.Debug, "DETACHED.");
            }
            else
            {
                thr.join();
                LOGP(applog.Debug, "Joined.");
            }
        }
    }

    void Worker();
};


struct Tunnelbox;

class Tunnel
{
	// 管理所有的网络隧道: 创建隧道/关闭隧道/资源回收
    Tunnelbox* parent_box;
	// 源和目的
    std::unique_ptr<Medium> med_acp, med_clr;
	// 双向传输: 源 < - > 目的
    Engine acp_to_clr, clr_to_acp;
    srt::sync::atomic<bool> running{true};
    std::mutex access;

public:

	// 输出一下源和目的的URI
    string show()
    {
        return med_acp->uri() + " <-> " + med_clr->uri();
    }

    Tunnel(Tunnelbox* m, std::unique_ptr<Medium>&& acp, std::unique_ptr<Medium>&& clr):
        parent_box(m),
        med_acp(std::move(acp)), med_clr(std::move(clr)),
        acp_to_clr(this, med_acp.get(), med_clr.get(), med_acp->id() + ">" + med_clr->id()),
        clr_to_acp(this, med_clr.get(), med_acp.get(), med_clr->id() + ">" + med_acp->id())
    {
    }

	// 启动双向传输
    void Start()
    {
    	// 源 -> 目的
        acp_to_clr.Start();
		// 目的 -> 源
		clr_to_acp.Start();
    }

    // This is to be called by an Engine from Engine::Worker
    // thread.
    // [[affinity = acp_to_clr.thr || clr_to_acp.thr]];

	// 关闭传输
    void decommission_engine(Medium* which_medium)
    {
        // which_medium is the medium that failed.
        // Upon breaking of one medium from the pair,
        // the other needs to be closed as well.
        Verb() << "Medium broken: " << which_medium->uri();

        bool stop = true;

        /*
        {
            lock_guard<std::mutex> lk(access);
            if (acp_to_clr.stat() == -1 && clr_to_acp.stat() == -1)
            {
                Verb() << "Tunnel: Both engine decommissioned, will stop the tunnel.";
                // Both engines are down, decommission the tunnel.
                // Note that the status -1 means that particular engine
                // is not currently running and you can safely
                // join its thread.
                stop = true;
            }
            else
            {
                Verb() << "Tunnel: Decommissioned one engine, waiting for the other one to report";
            }
        }
        */

        if (stop)
        {
            // First, stop all media.
            med_acp->Close();
            med_clr->Close();

            // Then stop the tunnel (this is only a signal
            // to a cleanup thread to delete it).
            Stop();
        }
    }

	// 关闭传输
    void Stop();

	// 当通道不可用时关闭，或强制退出通道
    bool decommission_if_dead(bool forced); // [[affinity = g_tunnels.thr]]
};


// 传输工作线程
void Engine::Worker()
{
    bytevector outbuf;

	// 初始化为输入媒介
    Medium* which_medium = media[DIR_IN];

    for (;;)
    {
        try
        {	
        	// 输入媒介
            which_medium = media[DIR_IN];
			// 从输入媒介中读数据
            rdst = media[DIR_IN]->Read((outbuf));
            switch (rdst)
            {

			// 从数据媒介中读数据，转发到输出媒介
            case Medium::RD_DATA:
                {
                    which_medium = media[DIR_OUT];
                    // We get the data, write them to the output
                    media[DIR_OUT]->Write((outbuf));
                }
                break;

			// 输入媒介关闭
            case Medium::RD_EOF:
                status = -1;
                throw Medium::ReadEOF("");

			// 输入媒介暂时不可用，请尝试再次读取
            case Medium::RD_AGAIN:
                // Theoreticall RD_AGAIN should not be reported
                // because it should be taken care of internally by
                // repeated sending - unless we get m_broken set.
                // If it is, however, it should be handled just like error.

			// 输入媒介读取失败
            case Medium::RD_ERROR:
                status = -1;
                Medium::Error("Error while reading");
            }
        }
		// 输入媒介关闭
        catch (Medium::ReadEOF&)
        {
            Verb() << "EOF. Exiting engine.";
            break;
        }
		// 传输出错
        catch (Medium::TransmissionError& er)
        {
            Verb() << er.what() << " - interrupting engine: " << nameid;
            break;
        }
    }

    // This is an engine thread and it should simply
    // tell the parent_box Tunnel that it is no longer
    // operative. It's not necessary to inform it which
    // of two engines is decommissioned - it should only
    // know that one of them got down. It will then check
    // if both are down here and decommission the whole
    // tunnel if so.

	// 如何输入和输出都被关闭了, 则关闭整个隧道
    parent_tunnel->decommission_engine(which_medium);
}

class SrtMedium: public Medium
{
    SRTSOCKET m_socket = SRT_ERROR;
    friend class Medium;
public:

#ifdef HAVE_FULL_CXX11
    using Medium::Medium;

#else // MSVC and gcc 4.7 not exactly support C++11

    SrtMedium(UriParser u, size_t ch): Medium(u, ch) {}

#endif

    bool IsOpen() override { return m_open; }
    bool End() override { return m_eof; }
    bool Broken() override { return m_broken; }

    void CloseSrt()
    {
        Verb() << "Closing SRT socket for " << uri();
        lock_guard<std::mutex> lk(access);
        if (m_socket == SRT_ERROR)
            return;
        srt_close(m_socket);
        m_socket = SRT_ERROR;
    }

    // Forwarded in order to separate the implementation from
    // the virtual function so that virtual function is not
    // being called in destructor.
    void CloseInternal() override { return CloseSrt(); }

    const char* type() override { return "srt"; }
    int ReadInternal(char* output, int size) override;
    bool IsErrorAgain() override;

    void Write(bytevector& portion) override;
    void CreateListener() override;
    void CreateCaller() override;
    unique_ptr<Medium> Accept() override;
    void Connect() override;

protected:
    void Init() override;

    void ConfigurePre();
    void ConfigurePost(SRTSOCKET socket);

    using Medium::Error;

    static void Error(UDT::ERRORINFO& ri, const string& text)
    {
        throw TransmissionError("ERROR: " + text + ": " + ri.getErrorMessage());
    }

    ~SrtMedium() override
    {
        CloseState();
        CloseSrt();
    }
};

class TcpMedium: public Medium
{
    int m_socket = -1;
    friend class Medium;
public:

#ifdef HAVE_FULL_CXX11
    using Medium::Medium;

#else // MSVC not exactly supports C++11

    TcpMedium(UriParser u, size_t ch): Medium(u, ch) {}

#endif

#ifdef _WIN32
    static int tcp_close(int socket)
    {
        return ::closesocket(socket);
    }

    enum { DEF_SEND_FLAG = 0 };

#elif defined(LINUX) || defined(GNU) || defined(CYGWIN)
    static int tcp_close(int socket)
    {
        return ::close(socket);
    }

    enum { DEF_SEND_FLAG = MSG_NOSIGNAL };

#else
    static int tcp_close(int socket)
    {
        return ::close(socket);
    }

    enum { DEF_SEND_FLAG = 0 };

#endif

    bool IsOpen() override { return m_open; }
    bool End() override { return m_eof; }
    bool Broken() override { return m_broken; }

    void CloseTcp()
    {
        Verb() << "Closing TCP socket for " << uri();
        lock_guard<std::mutex> lk(access);
        if (m_socket == -1)
            return;
        tcp_close(m_socket);
        m_socket = -1;
    }
    void CloseInternal() override { return CloseTcp(); }

    const char* type() override { return "tcp"; }
    int ReadInternal(char* output, int size) override;
    bool IsErrorAgain() override;
    void Write(bytevector& portion) override;
    void CreateListener() override;
    void CreateCaller() override;
    unique_ptr<Medium> Accept() override;
    void Connect() override;

protected:

    void ConfigurePre()
    {
#if defined(__APPLE__)
        int optval = 1;
        setsockopt(m_socket, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));
#endif
    }

    void ConfigurePost(int)
    {
    }

    using Medium::Error;

    static void Error(int verrno, const string& text)
    {
        char rbuf[1024];
        throw TransmissionError("ERROR: " + text + ": " + SysStrError(verrno, rbuf, 1024));
    }

    virtual ~TcpMedium()
    {
        CloseState();
        CloseTcp();
    }
};

void SrtMedium::Init()
{
    // This function is required due to extra option
    // check need

    if (m_options.count("mode"))
        Error("No option 'mode' is required, it defaults to position of the argument");

    if (m_options.count("blocking"))
        Error("Blocking is not configurable here.");

    // XXX
    // Look also for other options that should not be here.

    // Enforce the transtype = file
    m_options["transtype"] = "file";
}

void SrtMedium::ConfigurePre()
{
    vector<string> fails;
    m_options["mode"] = "caller";
    SrtConfigurePre(m_socket, "", m_options, &fails);
    if (!fails.empty())
    {
        cerr << "Failed options: " << Printable(fails) << endl;
    }
}

void SrtMedium::ConfigurePost(SRTSOCKET so)
{
    vector<string> fails;
    SrtConfigurePost(so, m_options, &fails);
    if (!fails.empty())
    {
        cerr << "Failed options: " << Printable(fails) << endl;
    }
}

void SrtMedium::CreateListener()
{
    int backlog = 5; // hardcoded!

    m_socket = srt_create_socket();

    ConfigurePre();

    sockaddr_any sa = CreateAddr(m_uri.host(), m_uri.portno());

    int stat = srt_bind(m_socket, sa.get(), sizeof sa);

    if ( stat == SRT_ERROR )
    {
        srt_close(m_socket);
        Error(UDT::getlasterror(), "srt_bind");
    }

    stat = srt_listen(m_socket, backlog);
    if ( stat == SRT_ERROR )
    {
        srt_close(m_socket);
        Error(UDT::getlasterror(), "srt_listen");
    }

    m_listener = true;
};

void TcpMedium::CreateListener()
{
    int backlog = 5; // hardcoded!


    sockaddr_any sa = CreateAddr(m_uri.host(), m_uri.portno());

    m_socket = (int)socket(sa.get()->sa_family, SOCK_STREAM, IPPROTO_TCP);
    ConfigurePre();

    int stat = ::bind(m_socket, sa.get(), sa.size());

    if (stat == -1)
    {
        tcp_close(m_socket);
        Error(errno, "bind");
    }

    stat = listen(m_socket, backlog);
    if ( stat == -1 )
    {
        tcp_close(m_socket);
        Error(errno, "listen");
    }

    m_listener = true;
}

unique_ptr<Medium> SrtMedium::Accept()
{
    sockaddr_any sa;
    SRTSOCKET s = srt_accept(m_socket, (sa.get()), (&sa.len));
    if (s == SRT_ERROR)
    {
        Error(UDT::getlasterror(), "srt_accept");
    }

    ConfigurePost(s);

    // Configure 1s timeout
    int timeout_1s = 1000;
    srt_setsockflag(m_socket, SRTO_RCVTIMEO, &timeout_1s, sizeof timeout_1s);

    unique_ptr<Medium> med(CreateAcceptor(this, sa, s, m_chunk));
    Verb() << "accepted a connection from " << med->uri();

    return med;
}

unique_ptr<Medium> TcpMedium::Accept()
{
    sockaddr_any sa;
    int s = (int)::accept(m_socket, (sa.get()), (&sa.syslen()));
    if (s == -1)
    {
        Error(errno, "accept");
    }

    // Configure 1s timeout
    timeval timeout_1s { 1, 0 };
    int st SRT_ATR_UNUSED = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_1s, sizeof timeout_1s);
    timeval re;
    socklen_t size = sizeof re;
    int st2 SRT_ATR_UNUSED = getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&re, &size);

    LOGP(applog.Debug, "Setting SO_RCVTIMEO to @", m_socket, ": ", st == -1 ? "FAILED" : "SUCCEEDED",
            ", read-back value: ", st2 == -1 ? int64_t(-1) : (int64_t(re.tv_sec)*1000000 + re.tv_usec)/1000, "ms");

    unique_ptr<Medium> med(CreateAcceptor(this, sa, s, m_chunk));
    Verb() << "accepted a connection from " << med->uri();

    return med;
}

void SrtMedium::CreateCaller()
{
    m_socket = srt_create_socket();
    ConfigurePre();

    // XXX setting up outgoing port not supported
}

void TcpMedium::CreateCaller()
{
    m_socket = (int)::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ConfigurePre();
}

void SrtMedium::Connect()
{
    sockaddr_any sa = CreateAddr(m_uri.host(), m_uri.portno());

    int st = srt_connect(m_socket, sa.get(), sizeof sa);
    if (st == SRT_ERROR)
        Error(UDT::getlasterror(), "srt_connect");

    ConfigurePost(m_socket);

    // Configure 1s timeout
    int timeout_1s = 1000;
    srt_setsockflag(m_socket, SRTO_RCVTIMEO, &timeout_1s, sizeof timeout_1s);
}

void TcpMedium::Connect()
{
    sockaddr_any sa = CreateAddr(m_uri.host(), m_uri.portno());

    int st = ::connect(m_socket, sa.get(), sa.size());
    if (st == -1)
        Error(errno, "connect");

    ConfigurePost(m_socket);

    // Configure 1s timeout
    timeval timeout_1s { 1, 0 };
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_1s, sizeof timeout_1s);
}

int SrtMedium::ReadInternal(char* w_buffer, int size)
{
    int st = -1;
    do
    {
        st = srt_recv(m_socket, (w_buffer), size);
        if (st == SRT_ERROR)
        {
            int syserr;
            if (srt_getlasterror(&syserr) == SRT_EASYNCRCV && !m_broken)
                continue;
        }
        break;

    } while (true);

    return st;
}

int TcpMedium::ReadInternal(char* w_buffer, int size)
{
    int st = -1;
    LOGP(applog.Debug, "TcpMedium:recv @", m_socket, " - begin");
    do
    {
        st = ::recv(m_socket, (w_buffer), size, 0);
        if (st == -1)
        {
            if ((errno == EAGAIN || errno == EWOULDBLOCK))
            {
                if (!m_broken)
                {
                    LOGP(applog.Debug, "TcpMedium: read:AGAIN, repeating");
                    continue;
                }
                LOGP(applog.Debug, "TcpMedium: read:AGAIN, not repeating - already broken");
            }
            else
            {
                LOGP(applog.Debug, "TcpMedium: read:ERROR: ", errno);
            }
        }
        break;
    } while (true);
    LOGP(applog.Debug, "TcpMedium:recv @", m_socket, " - result: ", st);
    return st;
}

bool SrtMedium::IsErrorAgain()
{
    return srt_getlasterror(NULL) == SRT_EASYNCRCV;
}

bool TcpMedium::IsErrorAgain()
{
    return errno == EAGAIN;
}

// The idea of Read function is to get the buffer that
// possibly contains some data not written to the output yet,
// but the time has come to read. We can't let the buffer expand
// more than the size of the chunk, so if the buffer size already
// exceeds it, don't return any data, but behave as if they were read.
// This will cause the worker loop to redirect to Write immediately
// thereafter and possibly will flush out the remains of the buffer.
// It's still possible that the buffer won't be completely purged
Medium::ReadStatus Medium::Read(bytevector& w_output)
{
    // Don't read, but fake that you read
    // 缓冲区中的数据量超过预设的数据块大小，返回RD_DATA，让用户先处理缓冲区中的数据，等缓冲区清空后再进行读取
    if (w_output.size() > m_chunk)
    {
        Verb() << "BUFFER EXCEEDED";
        return RD_DATA;
    }

    // Resize to maximum first
    // 输入流已经读到了末尾，但是此时缓冲区中仍有数据
    // 此时不应该返回RD_EOF,而是返回RD_DATA，表示缓冲区中仍有数据尚未处理
    size_t shift = w_output.size();
    if (shift && m_eof)
    {
        // You have nonempty buffer, but eof was already
        // encountered. Report as if something was read.
        //
        // Don't read anything because this will surely
        // result in error since now.
        return RD_DATA;
    }

    // 预期的数据量大小: 当前缓冲区中的数据量 + 预设的数据块大小
    size_t pred_size = shift + m_chunk;

    // 调整缓冲区大小
    w_output.resize(pred_size);
    // 从媒体流中读取数据
    int st = ReadInternal((w_output.data() + shift), (int)m_chunk);
    if (st == -1)
    {
        if (IsErrorAgain())
            return RD_AGAIN;

        return RD_ERROR;
    }

    // 读取到的数据量为0，表示媒体流已经结束，读到了EOF
    if (st == 0)
    {
        // 设置EOF标志位
        m_eof = true;
        // 如果缓冲区中仍有数据，则返回RD_DATA，表示缓冲区中仍有数据尚未处理
        if (shift)
        {
            // If there's 0 (eof), but you still have data
            // in the buffer, fake that they were read. Only
            // when the buffer was empty at entrance should this
            // result with EOF.
            //
            // Set back the size this buffer had before we attempted
            // to read into it.
            w_output.resize(shift);
            return RD_DATA;
        }

        w_output.clear();
        return RD_EOF;
    }

    // 调整缓冲区大小
    w_output.resize(shift+st);
    return RD_DATA;
}

void SrtMedium::Write(bytevector& w_buffer)
{
    int st = srt_send(m_socket, w_buffer.data(), (int)w_buffer.size());
    if (st == SRT_ERROR)
    {
        Error(UDT::getlasterror(), "srt_send");
    }

    // This should be ==, whereas > is not possible, but
    // this should simply embrace this case as a sanity check.
    if (st >= int(w_buffer.size()))
        w_buffer.clear();
    else if (st == 0)
    {
        Error("Unexpected EOF on Write");
    }
    else
    {
        // Remove only those bytes that were sent
        w_buffer.erase(w_buffer.begin(), w_buffer.begin()+st);
    }
}

void TcpMedium::Write(bytevector& w_buffer)
{
    int st = ::send(m_socket, w_buffer.data(), (int)w_buffer.size(), DEF_SEND_FLAG);
    if (st == -1)
    {
        Error(errno, "send");
    }

    // This should be ==, whereas > is not possible, but
    // this should simply embrace this case as a sanity check.
    if (st >= int(w_buffer.size()))
        w_buffer.clear();
    else if (st == 0)
    {
        Error("Unexpected EOF on Write");
    }
    else
    {
        // Remove only those bytes that were sent
        w_buffer.erase(w_buffer.begin(), w_buffer.begin()+st);
    }
}

// 根据URI创建一个SRT或TCP媒体流
std::unique_ptr<Medium> Medium::Create(const std::string& url, size_t chunk, Medium::Mode mode)
{
    // 解析URI
    UriParser uri(url);
    std::unique_ptr<Medium> out;

    // Might be something smarter, but there are only 2 types.

    // 创建一个SRT媒体流
    if (uri.scheme() == "srt")
    {
        out.reset(new SrtMedium(uri, chunk));
    }
    // 创建要给TCP媒体流
    else if (uri.scheme() == "tcp")
    {
        out.reset(new TcpMedium(uri, chunk));
    }
    else
    {
        Error("Medium not supported");
    }

    // 初始化模式: listener/caller,创建一个listener或caller
    out->InitMode(mode);

    return out;
}

// 管理所有的网络隧道: 创建隧道/关闭隧道/资源回收
struct Tunnelbox
{
	// 存储隧道对象的列表
    list<unique_ptr<Tunnel>> tunnels;
    std::mutex access;
	// 条件变量，用于通知清理操作
    condition_variable decom_ready;
	// 标记主程序是否在运行
    bool main_running = true;
	// 清理线程
    thread thr;

	// 关闭隧道的信号
    void signal_decommission()
    {
        lock_guard<std::mutex> lk(access);
        decom_ready.notify_one();
    }

	// 创建一个隧道
    void install(std::unique_ptr<Medium>&& acp, std::unique_ptr<Medium>&& clr)
    {
        lock_guard<std::mutex> lk(access);
        Verb() << "Tunnelbox: Starting tunnel: " << acp->uri() << " <-> " << clr->uri();

        tunnels.emplace_back(new Tunnel(this, std::move(acp), std::move(clr)));
        // Note: after this instruction, acp and clr are no longer valid!
        auto& it = tunnels.back();

		// 
        it->Start();
    }

	// 创建资源回收线程
    void start_cleaner()
    {
        thr = thread( [this]() { CleanupWorker(); } );
    }

	// 停止资源回收线程
    void stop_cleaner()
    {
        if (thr.joinable())
            thr.join();
    }

private:

	// 资源回收线程
    void CleanupWorker()
    {
        unique_lock<std::mutex> lk(access);

        while (main_running)
        {
            decom_ready.wait(lk);

            // Got a signal, find a tunnel ready to cleanup.
            // We just get the signal, but we don't know which
            // tunnel has generated it.
            for (auto i = tunnels.begin(), i_next = i; i != tunnels.end(); i = i_next)
            {
                ++i_next;
                // Bound in one call the check if the tunnel is dead
                // and decommissioning because this must be done in
                // the one critical section - make sure no other thread
                // is accessing it at the same time and also make join all
                // threads that might have been accessing it. After
                // exiting as true (meaning that it was decommissioned
                // as expected) it can be safely deleted.
                if ((*i)->decommission_if_dead(main_running))
                {
                    tunnels.erase(i);
                }
            }
        }
    }
};

// 关闭传输
void Tunnel::Stop()
{
    // Check for running must be done without locking
    // because if the tunnel isn't running
    if (!running)
        return; // already stopped

    lock_guard<std::mutex> lk(access);

    // Ok, you are the first to make the tunnel
    // not running and inform the tunnelbox.
    running = false;
    parent_box->signal_decommission();
}

// 如果隧道不可用或需要强制退出时，关闭之
bool Tunnel::decommission_if_dead(bool forced)
{
    lock_guard<std::mutex> lk(access);
    if (running && !forced)
        return false; // working, not to be decommissioned

    // Join the engine threads, make sure nothing
    // is running that could use the data.
    acp_to_clr.Stop();
    clr_to_acp.Stop();


    // Done. The tunnelbox after calling this can
    // safely delete the decommissioned tunnel.
    return true;
}

// 初始ID
int Medium::s_counter = 1;

Tunnelbox g_tunnels;
std::unique_ptr<Medium> main_listener;

size_t default_chunk = 4096;

int OnINT_StopService(int)
{
    g_tunnels.main_running = false;
    g_tunnels.signal_decommission();

    // Will cause the Accept() block to exit.
    main_listener->Close();

    return 0;
}

// ./srt-tunnel <listen-uri> <call-uri>
int main( int argc, char** argv )
{
	// windows下需要初始化网络模块
    if (!SysInitializeNetwork())
    {
        cerr << "Fail to initialize network module.";
        return 1;
    }

	// 一次读取的数据量，默认=4096字节
    size_t chunk = default_chunk;

	// 命令行选项
    OptionName
        o_loglevel = { "ll", "loglevel" },		// 日志记录级别，默认：错误
        o_logfa = { "lf", "logfa" },			// 启用日志记录的功能区域
        o_chunk = {"c", "chunk" },				// 一次读取的数据量，默认=4096字节
        o_verbose = {"v", "verbose" },			// 显示详细信息
        o_noflush = {"s", "skipflush" };		// 退出而不等待剩余数据传输完成

    // Options that expect no arguments (ARG_NONE) need not be mentioned.

	// 命令行参数
    vector<OptionScheme> optargs = {
        { o_loglevel, OptionScheme::ARG_ONE },
        { o_logfa, OptionScheme::ARG_ONE },
        { o_chunk, OptionScheme::ARG_ONE }
    };

	// 解析命令行参数，保存到map params中
    options_t params = ProcessOptions(argv, argc, optargs);

    /*
       cerr << "OPTIONS (DEBUG)\n";
       for (auto o: params)
       {
       cerr << "[" << o.first << "] ";
       copy(o.second.begin(), o.second.end(), ostream_iterator<string>(cerr, " "));
       cerr << endl;
       }
     */

	// 两个不带选项的参数保存在空键中, <listen-uri> <call-uri>
    vector<string> args = params[""];
    if ( args.size() < 2 )
    {
        cerr << "Usage: " << argv[0] << " <listen-uri> <call-uri>\n";
        return 1;
    }

	// 日志系统初始化
    string loglevel = Option<OutString>(params, "error", o_loglevel);
    string logfa = Option<OutString>(params, "", o_logfa);
    srt_logging::LogLevel::type lev = SrtParseLogLevel(loglevel);
    srt::setloglevel(lev);
    if (logfa == "")
    {
        srt::addlogfa(SRT_LOGFA_APP);
    }
    else
    {
        // Add only selected FAs
        set<string> unknown_fas;
        set<srt_logging::LogFA> fas = SrtParseLogFA(logfa, &unknown_fas);
        srt::resetlogfa(fas);

        // The general parser doesn't recognize the "app" FA, we check it here.
        if (unknown_fas.count("app"))
            srt::addlogfa(SRT_LOGFA_APP);
    }

	// 是否输出详细日志
    string verbo = Option<OutString>(params, "no", o_verbose);
    if ( verbo == "" || !false_names.count(verbo) )
    {
        Verbose::on = true;
        Verbose::cverb = &std::cout;
    }

	// 一次读取的数据量
    string chunks = Option<OutString>(params, "", o_chunk);
    if ( chunks!= "" )
    {
        chunk = stoi(chunks);
    }

    string listen_node = args[0];
    string call_node = args[1];

	// uri地址
    UriParser ul(listen_node), uc(call_node);

    // It is allowed to use both media of the same type,
    // but only srt and tcp are allowed.

	// 只支持srt和tcp

    set<string> allowed = {"srt", "tcp"};
    if (!allowed.count(ul.scheme())|| !allowed.count(uc.scheme()))
    {
        cerr << "ERROR: only tcp and srt schemes supported";
        return -1;
    }

    Verb() << "LISTEN type=" << ul.scheme() << ", CALL type=" << uc.scheme();

	// 启动资源回收线程
    g_tunnels.start_cleaner();

	// 创建一个输入媒介，即源URI
    main_listener = Medium::Create(listen_node, chunk, Medium::LISTENER);

    // The main program loop is only to catch
    // new connections and manage them. Also takes care
    // of the broken connections.

    for (;;)
    {
        try
        {
        	// 接受连接
            Verb() << "Waiting for connection...";
            std::unique_ptr<Medium> accepted = main_listener->Accept();
            if (!g_tunnels.main_running)
            {
                Verb() << "Service stopped. Exiting.";
                break;
            }
            Verb() << "Connection accepted. Connecting to the relay...";

            // Now call the target address.
            std::unique_ptr<Medium> caller = Medium::Create(call_node, chunk, Medium::CALLER);
            caller->Connect();

            Verb() << "Connected. Establishing pipe.";

            // No exception, we are free to pass :)
            g_tunnels.install(std::move(accepted), std::move(caller));
        }
        catch (...)
        {
            Verb() << "Connection reported, but failed";
        }
    }

    g_tunnels.stop_cleaner();

    return 0;
}


