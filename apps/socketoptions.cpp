/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

#include "socketoptions.hpp"
#include "verbose.hpp"

using namespace std;

// 可以表示true的一系列字符串集合
extern const set<string> true_names = { "1", "yes", "on", "true" };
// 可以表示为false的一系列字符串集合
extern const set<string> false_names = { "0", "no", "off", "false" };

extern const std::map<std::string, int> enummap_transtype = {
    { "live", SRTT_LIVE },
    { "file", SRTT_FILE }
};


const char* const SocketOption::mode_names[3] = {
    "listener", "caller", "rendezvous"
};

// 确定SRT连接模式: Listener/Caller/Rendezvous
SocketOption::Mode SrtInterpretMode(const string& modestr, const string& host, const string& adapter)
{
    SocketOption::Mode mode = SocketOption::FAILURE;

    if (modestr == "client" || modestr == "caller")
    {
        mode = SocketOption::CALLER;
    }
    else if (modestr == "server" || modestr == "listener")
    {
        mode = SocketOption::LISTENER;
    }
    else if (modestr == "rendezvous")
    {
        mode = SocketOption::RENDEZVOUS;
    }
    else if (modestr == "default")
    {
        // Use the following convention:
        // 1. Server for source, Client for target
        // 2. If host is empty, then always server.

        /*
            1. URI中未指定host，则说明是作为服务器，如 srt://:9000;
                1.1 这里有一个疑问：如果是 srt://0.0.0.0:9000或srt://127.0.0.1:9000呢？难道此时就不是LISTENER模式了？
                1.2 哦！原来在https://github.com/Haivision/srt/blob/master/docs/apps/srt-live-transmit.md
                    这个文档中明确规定了:在这种情况下，必须使用mode参数明确指定连接模式
            2. 如果URI中指定了host，则说明是作为客户端，此时需要检查适配器
                2.1 URI中未指定网络适配器，说明是普通连接，如 srt://101.230.251.172:9000
                2.2 URI中指定了网络适配器，说明是交会连接模式，如 srt://peer:9000?adapter=192.168.1.10
        */

        if ( host == "" )
            mode = SocketOption::LISTENER;
        //else if ( !dir_output )
        //mode = "server";
        else
        {
            // Host is given, so check also "adapter"
            if (adapter != "")
                mode = SocketOption::RENDEZVOUS;
            else
                mode = SocketOption::CALLER;
        }
    }
    else
    {
        mode = SocketOption::FAILURE;
    }

    return mode;
}

/*
    SRT连接前的配置:
        1. 连接模式
        2. 网络适配器设置
        3. 延迟关闭设置
        4. 检查需要设置的参数是否都已经设置成功了
*/
SocketOption::Mode SrtConfigurePre(SRTSOCKET socket, string host, map<string, string> options, vector<string>* failures)
{
    vector<string> dummy;
    vector<string>& fails = failures ? *failures : dummy;

    string modestr = "default", adapter;

    // 连接模式: listener/caller/rendezvous
    if (options.count("mode"))
    {
        modestr = options["mode"];
    }

    // 网络适配器
    if (options.count("adapter"))
    {
        adapter = options["adapter"];
    }

    // 修正连接模式
    SocketOption::Mode mode = SrtInterpretMode(modestr, host, adapter);
    if (mode == SocketOption::FAILURE)
    {
        fails.push_back("mode");
    }

    // 延时关闭时间- 关闭时等待未发送的数据，即如果关闭时仍有数据尚未发送，等待一段时间
    if (options.count("linger"))
    {
        linger lin;
        // 延时时间
        lin.l_linger = stoi(options["linger"]);
        // 开启/关闭
        lin.l_onoff  = lin.l_linger > 0 ? 1 : 0;
        srt_setsockopt(socket, SocketOption::PRE, SRTO_LINGER, &lin, sizeof(linger));
    }


    // 检查需要设置的参数是否都已经设置成功了
    bool all_clear = true;
    for (const auto &o: srt_options)
    {
        if ( o.binding == SocketOption::PRE && options.count(o.name) )
        {
            string value = options.at(o.name);
            bool ok = o.apply<SocketOption::SRT>(socket, value);
            if ( !ok )
            {
                fails.push_back(o.name);
                all_clear = false;
            }
        }
    }

    return all_clear ? mode : SocketOption::FAILURE;
}

void SrtConfigurePost(SRTSOCKET socket, map<string, string> options, vector<string>* failures)
{
    vector<string> dummy;
    vector<string>& fails = failures ? *failures : dummy;

    for (const auto &o: srt_options)
    {
        if ( o.binding == SocketOption::POST && options.count(o.name) )
        {
            string value = options.at(o.name);
            Verb() << "Setting option: " << o.name << " = " << value;
            bool ok = o.apply<SocketOption::SRT>(socket, value);
            if ( !ok )
                fails.push_back(o.name);
        }
    }
}

