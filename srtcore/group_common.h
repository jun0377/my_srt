/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2021 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

/*****************************************************************************
Written by
   Haivision Systems Inc.
*****************************************************************************/

#ifndef INC_SRT_GROUP_COMMON_H
#define INC_SRT_GROUP_COMMON_H

#include "srt.h"
#include "common.h"
#include "core.h"

#include <list>

namespace srt
{
namespace groups
{
    // 套接字组中的SRT套接字状态：PENDING、IDLE、RUNNING、BROKEN
    typedef SRT_MEMBERSTATUS GroupState;

    struct SocketData
    {
        // SRT套接字ID
        SRTSOCKET      id; // same as ps->m_SocketID
        // 指向CUDTSocket的指针
        CUDTSocket*    ps;
        // token
        int            token;
        // SRT套接字本身的状态: 创建、绑定、监听、连接、关闭
        SRT_SOCKSTATUS laststatus;
        // SRT套接字在组中的状态: PENDING、IDLE、RUNNING、BROKEN
        GroupState     sndstate;
        // SRT套接字接收状态
        GroupState     rcvstate;
        // 发送数据时的返回值
        int            sndresult;
        // 接收数据时的返回值
        int            rcvresult;
        // 代理地址
        sockaddr_any   agent;
        // 对端地址
        sockaddr_any   peer;
        // 是否可读
        bool           ready_read;
        // 是否可写
        bool           ready_write;
        // 是否出错
        bool           ready_error;

        // Configuration
        // 流量分配权重?
        uint16_t       weight;

        // Stats
        // 发送丢包统计
        int64_t        pktSndDropTotal;
    };

    // 准备套接字相关信息
    SocketData prepareSocketData(CUDTSocket* s);

    // 套接字组
    typedef std::list<SocketData> group_t;
    typedef group_t::iterator     gli_t;

} // namespace groups
} // namespace srt

#endif // INC_SRT_GROUP_COMMON_H
