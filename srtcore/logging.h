/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

/*****************************************************************************
written by
   Haivision Systems Inc.
 *****************************************************************************/

#ifndef INC_SRT_LOGGING_H
#define INC_SRT_LOGGING_H


#include <iostream>
#include <iomanip>
#include <set>
#include <sstream>
#include <cstdarg>
#ifdef _WIN32
#include "win/wintime.h"
#include <sys/timeb.h>
#else
#include <sys/time.h>
#endif

#include "srt.h"
#include "utilities.h"
#include "threadname.h"
#include "logging_api.h"
#include "sync.h"

#ifdef __GNUC__
#define PRINTF_LIKE __attribute__((format(printf,2,3)))
#else
#define PRINTF_LIKE 
#endif

#if ENABLE_LOGGING

// GENERAL NOTE: All logger functions ADD THEIR OWN \n (EOL). Don't add any your own EOL character.
// The logging system may not add the EOL character, if appropriate flag was set in log settings.
// Anyway, treat the whole contents of eventually formatted message as exactly one line.

// LOGC uses an iostream-like syntax, using the special 'log' symbol.
// This symbol isn't visible outside the log macro parameters.
// Usage: LOGC(gglog.Debug, log << param1 << param2 << param3);
#define LOGC(logdes, args) if (logdes.CheckEnabled()) \
{ \
    srt_logging::LogDispatcher::Proxy log(logdes); \
    log.setloc(__FILE__, __LINE__, __FUNCTION__); \
    { (void)(const srt_logging::LogDispatcher::Proxy&)(args); } \
}

// LOGF uses printf-like style formatting.
// Usage: LOGF(gglog.Debug, "%s: %d", param1.c_str(), int(param2));
// NOTE: LOGF is deprecated and should not be used
#define LOGF(logdes, ...) if (logdes.CheckEnabled()) logdes().setloc(__FILE__, __LINE__, __FUNCTION__).form(__VA_ARGS__)

// LOGP is C++11 only OR with only one string argument.
// Usage: LOGP(gglog.Debug, param1, param2, param3);
#define LOGP(logdes, ...) if (logdes.CheckEnabled()) logdes.printloc(__FILE__, __LINE__, __FUNCTION__,##__VA_ARGS__)

#define IF_LOGGING(instr) instr

#if ENABLE_HEAVY_LOGGING

#define HLOGC LOGC
#define HLOGP LOGP
#define HLOGF LOGF

#define IF_HEAVY_LOGGING(instr,...) instr,##__VA_ARGS__

#else

#define HLOGC(...)
#define HLOGF(...)
#define HLOGP(...)

#define IF_HEAVY_LOGGING(instr) (void)0

#endif

#else

#define LOGC(...)
#define LOGF(...)
#define LOGP(...)

#define HLOGC(...)
#define HLOGF(...)
#define HLOGP(...)

#define IF_HEAVY_LOGGING(instr) (void)0
#define IF_LOGGING(instr) (void)0

#endif

namespace srt_logging
{

struct LogConfig
{
    // 功能取域位图64bits，决定开启哪些功能相关的日志
    typedef std::bitset<SRT_LOGFA_LASTNONE+1> fa_bitset_t;
    // 开启日志的模块
    fa_bitset_t enabled_fa;   // NOTE: assumed atomic reading
    // 日志等级
    LogLevel::type max_level; // NOTE: assumed atomic reading
    // 日志输出流
    std::ostream* log_stream;
    // 日志处理函数
    SRT_LOG_HANDLER_FN* loghandler_fn;
    // 日志处理函数参数
    void* loghandler_opaque;
    // 互斥锁
    mutable srt::sync::Mutex mutex;
    // 日志标志:是否显示时间/线程名称/日志等级/自动添加换行符
    int flags;

    LogConfig(const fa_bitset_t& efa,
            LogLevel::type l = LogLevel::warning,
            std::ostream* ls = &std::cerr)
        : enabled_fa(efa)
        , max_level(l)
        , log_stream(ls)
        , loghandler_fn()
        , loghandler_opaque()
        , flags()
    {
    }

    ~LogConfig()
    {
    }

    SRT_ATTR_ACQUIRE(mutex)
    void lock() const { mutex.lock(); }

    SRT_ATTR_RELEASE(mutex)
    void unlock() const { mutex.unlock(); }
};

// The LogDispatcher class represents the object that is responsible for
// a decision whether to log something or not, and if so, print the log.
// 日志分发器,负责处理和格式化日志
struct SRT_API LogDispatcher
{
private:
    // 功能域
    int fa;
    // 日志等级
    LogLevel::type level;
    // 日志前缀最大长度
    static const size_t MAX_PREFIX_SIZE = 32;
    // 日志前缀
    char prefix[MAX_PREFIX_SIZE+1];
    // 日志前缀长度
    size_t prefix_len;
    // 日志配置
    LogConfig* src_config;

    // 检查日志某个标志是否开启
    bool isset(int flg) { return (src_config->flags & flg) != 0; }

public:

    /*
        日志前缀
            1. 允许用户自定义日志前缀
            2. 日志记录器有一个默认的内部日志前缀
            3. 日志前缀 = 用户自定义前缀 + ":" + 内部前缀
            4. 日志前缀长度不能超过MAX_PREFIX_SIZE
            5. 如果日志前缀长度超出限制，则只使用用户自定义前缀
    */
    LogDispatcher(int functional_area, LogLevel::type log_level, const char* your_pfx,
            const char* logger_pfx /*[[nullable]]*/, LogConfig& config):
        fa(functional_area),
        level(log_level),
        src_config(&config)
    {
        // 用户自定义日志前缀长度
        const size_t your_pfx_len = your_pfx ? strlen(your_pfx) : 0;
        // 内部日志前缀长度
        const size_t logger_pfx_len = logger_pfx ? strlen(logger_pfx) : 0;

        // 日志前缀长度没有超出限制，日志前缀 = 用户自定义前缀 + ":" + 内部前缀
        if (logger_pfx && your_pfx_len + logger_pfx_len + 1 < MAX_PREFIX_SIZE)
        {
            memcpy(prefix, your_pfx, your_pfx_len);
            prefix[your_pfx_len] = ':';
            memcpy(prefix + your_pfx_len + 1, logger_pfx, logger_pfx_len);
            prefix[your_pfx_len + logger_pfx_len + 1] = '\0';
            prefix_len = your_pfx_len + logger_pfx_len + 1;
        }
        // 前缀长度超出限制，只使用用户自定义前缀
        else if (your_pfx)
        {
            // Prefix too long, so copy only your_pfx and only
            // as much as it fits
            size_t copylen = std::min(+MAX_PREFIX_SIZE, your_pfx_len);
            memcpy(prefix, your_pfx, copylen);
            prefix[copylen] = '\0';
            prefix_len = copylen;
        }
        // 没有日志前缀
        else
        {
            prefix[0] = '\0';
            prefix_len = 0;
        }
    }

    ~LogDispatcher()
    {
    }

    // 检查是否应该输出日志
    bool CheckEnabled();

    // 生成日志前缀: 时间/线程名称 日志等级
    void CreateLogLinePrefix(std::ostringstream&);

    /*
    日志的两种输出方式:
        1. 用户指定日志处理函数，比如用户可以实现一个日志处理函数，将日志输出到文件
        2. 用户指定日志输出流
    */
    void SendLogLine(const char* file, int line, const std::string& area, const std::string& sl);

    // log.Debug("This is the ", nth, " time");  <--- C++11 only.
    // log.Debug() << "This is the " << nth << " time";  <--- C++03 available.

#if HAVE_CXX11

    // 输出日志
    template <class... Args>
    void PrintLogLine(const char* file, int line, const std::string& area, Args&&... args);

    // 重载()运算符，成为一个仿函数，使得可以采用logDispatcher(arg1, arg2, arg3)的方式输出日志
    template<class... Args>
    void operator()(Args&&... args)
    {
        PrintLogLine("UNKNOWN.c++", 0, "UNKNOWN", args...);
    }

    // 输出日志，允许指定文件名/行号/功能域
    template<class... Args>
    void printloc(const char* file, int line, const std::string& area, Args&&... args)
    {
        PrintLogLine(file, line, area, args...);
    }
#else
    template <class Arg>
    void PrintLogLine(const char* file, int line, const std::string& area, const Arg& arg);

    // For C++03 (older) standard provide only with one argument.
    template <class Arg>
    void operator()(const Arg& arg)
    {
        PrintLogLine("UNKNOWN.c++", 0, "UNKNOWN", arg);
    }

    void printloc(const char* file, int line, const std::string& area, const std::string& arg1)
    {
        PrintLogLine(file, line, area, arg1);
    }
#endif

#if ENABLE_LOGGING

    struct Proxy;
    friend struct Proxy;

    Proxy operator()();
#else

    // Dummy proxy that does nothing
    struct DummyProxy
    {
        DummyProxy(LogDispatcher&)
        {
        }

        template <class T>
        DummyProxy& operator<<(const T& ) // predicted for temporary objects
        {
            return *this;
        }

        // DEPRECATED: DO NOT use LOGF/HLOGF macros anymore.
        // Use iostream-style formatting with LOGC or a direct argument with LOGP.
        SRT_ATR_DEPRECATED_PX DummyProxy& form(const char*, ...) SRT_ATR_DEPRECATED
        {
            return *this;
        }

        DummyProxy& vform(const char*, va_list)
        {
            return *this;
        }

        DummyProxy& setloc(const char* , int , std::string)
        {
            return *this;
        }
    };

    DummyProxy operator()()
    {
        return DummyProxy(*this);
    }

#endif

};

#if ENABLE_LOGGING

/*
    代理模式:

*/
struct LogDispatcher::Proxy
{
    LogDispatcher& that;

    std::ostringstream os;

    // Cache the 'enabled' state in the beginning. If the logging
    // becomes enabled or disabled in the middle of the log, we don't
    // want it to be partially printed anyway.

    // 日志是否启用
    bool that_enabled;
    // 日志标志
    int flags;

    // CACHE!!!
    const char* i_file;
    int i_line;
    std::string area;

    Proxy& setloc(const char* f, int l, std::string a)
    {
        i_file = f;
        i_line = l;
        area = a;
        return *this;
    }

    // Left for future. Not sure if it's more convenient
    // to use this to translate __PRETTY_FUNCTION__ to
    // something short, or just let's leave __FUNCTION__
    // or better __func__.
    std::string ExtractName(std::string pretty_function);

    Proxy(LogDispatcher& guy);

    // Copy constructor is needed due to noncopyable ostringstream.
    // This is used only in creation of the default object, so just
    // use the default values, just copy the location cache.
    Proxy(const Proxy& p): that(p.that), area(p.area)
    {
        i_file = p.i_file;
        i_line = p.i_line;
        that_enabled = false;
        flags = p.flags;
    }


    template <class T>
    Proxy& operator<<(const T& arg) // predicted for temporary objects
    {
        if ( that_enabled )
        {
            os << arg;
        }
        return *this;
    }

    ~Proxy()
    {
        if (that_enabled)
        {
            if ((flags & SRT_LOGF_DISABLE_EOL) == 0)
                os << std::endl;
            that.SendLogLine(i_file, i_line, area, os.str());
        }
        // Needed in destructor?
        //os.clear();
        //os.str("");
    }

    Proxy& form(const char* fmts, ...) PRINTF_LIKE
    {
        if ( !that_enabled )
            return *this;

        if ( !fmts || fmts[0] == '\0' )
            return *this;

        va_list ap;
        va_start(ap, fmts);
        vform(fmts, ap);
        va_end(ap);
        return *this;
    }

    Proxy& vform(const char* fmts, va_list ap)
    {
        char buf[512];

#if defined(_MSC_VER) && _MSC_VER < 1900
        _vsnprintf(buf, sizeof(buf) - 1, fmts, ap);
#else
        vsnprintf(buf, sizeof(buf), fmts, ap);
#endif
        size_t len = strlen(buf);
        if ( buf[len-1] == '\n' )
        {
            // Remove EOL character, should it happen to be at the end.
            // The EOL will be added at the end anyway.
            buf[len-1] = '\0';
        }

        os.write(buf, len);
        return *this;
    }
};


#endif

// 日志记录器
class Logger
{
    // 日志功能域，表示哪些功能模块开启了日志:比如连接管理、拥塞控制、等不同的功能域
    int m_fa;
    // 日志配置
    LogConfig& m_config;

public:

    // 日志分发器
    LogDispatcher Debug;
    LogDispatcher Note;
    LogDispatcher Warn;
    LogDispatcher Error;
    LogDispatcher Fatal;

    Logger(int functional_area, LogConfig& config, const char* logger_pfx = NULL):
        m_fa(functional_area),
        m_config(config),
        Debug ( m_fa, LogLevel::debug, " D", logger_pfx, m_config ),
        Note  ( m_fa, LogLevel::note,  ".N", logger_pfx, m_config ),
        Warn  ( m_fa, LogLevel::warning, "!W", logger_pfx, m_config ),
        Error ( m_fa, LogLevel::error, "*E", logger_pfx, m_config ),
        Fatal ( m_fa, LogLevel::fatal, "!!FATAL!!", logger_pfx, m_config )
    {
    }
};

// 检查是否应该输出日志
inline bool LogDispatcher::CheckEnabled()
{
    // Don't use enabler caching. Check enabled state every time.

    // These assume to be atomically read, so the lock is not needed
    // (note that writing to this field is still mutex-protected).
    // It's also no problem if the level was changed at the moment
    // when the enabler check is tested here. Worst case, the log
    // will be printed just a moment after it was turned off.
    const LogConfig* config = src_config; // to enforce using const operator[]
    config->lock();
    // 检查响应功能域的日志是否启用
    int configured_enabled_fa = config->enabled_fa[fa];
    // 检查日志等级
    int configured_maxlevel = config->max_level;
    config->unlock();

    return configured_enabled_fa && level <= configured_maxlevel;
}


#if HAVE_CXX11

//extern std::mutex Debug_mutex;

inline void PrintArgs(std::ostream&) {}

template <class Arg1, class... Args>
inline void PrintArgs(std::ostream& serr, Arg1&& arg1, Args&&... args)
{
    serr << std::forward<Arg1>(arg1);
    PrintArgs(serr, args...);
}

template <class... Args>
// 输出日志
inline void LogDispatcher::PrintLogLine(const char* file SRT_ATR_UNUSED, int line SRT_ATR_UNUSED, const std::string& area SRT_ATR_UNUSED, Args&&... args SRT_ATR_UNUSED)
{
#ifdef ENABLE_LOGGING
    // 日志流
    std::ostringstream serr;
    // 生成日志前缀
    CreateLogLinePrefix(serr);
    // 输出日志内容
    PrintArgs(serr, args...);
    // 如果禁止自动添加换行符，则手动添加换行符
    if ( !isset(SRT_LOGF_DISABLE_EOL) )
        serr << std::endl;

    // Not sure, but it wasn't ever used.
    SendLogLine(file, line, area, serr.str());
#endif
}

#else // !HAVE_CXX11

template <class Arg>
inline void LogDispatcher::PrintLogLine(const char* file SRT_ATR_UNUSED, int line SRT_ATR_UNUSED, const std::string& area SRT_ATR_UNUSED, const Arg& arg SRT_ATR_UNUSED)
{
#ifdef ENABLE_LOGGING
    std::ostringstream serr;
    CreateLogLinePrefix(serr);
    serr << arg;

    if ( !isset(SRT_LOGF_DISABLE_EOL) )
        serr << std::endl;

    // Not sure, but it wasn't ever used.
    SendLogLine(file, line, area, serr.str());
#endif
}

#endif // HAVE_CXX11

// SendLogLine can be compiled normally. It's intermediately used by:
// - Proxy object, which is replaced by DummyProxy when !ENABLE_LOGGING
// - PrintLogLine, which has empty body when !ENABLE_LOGGING
/*
    日志的两种输出方式:
        1. 用户指定日志处理函数，比如用户可以实现一个日志处理函数，将日志输出到文件
        2. 用户指定日志输出流
*/
inline void LogDispatcher::SendLogLine(const char* file, int line, const std::string& area, const std::string& msg)
{
    src_config->lock();

    // 如果用户指定了日志处理函数，则调用用户指定的日志处理函数
    if ( src_config->loghandler_fn )
    {
        (*src_config->loghandler_fn)(src_config->loghandler_opaque, int(level), file, line, area.c_str(), msg.c_str());
    }
    // 如果用户指定了日志输出流，则将日志写入到输出流
    else if ( src_config->log_stream )
    {
        src_config->log_stream->write(msg.data(), msg.size());
        (*src_config->log_stream).flush();
    }
    
    src_config->unlock();
}

}

#endif // INC_SRT_LOGGING_H
