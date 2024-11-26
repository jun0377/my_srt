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
Copyright (c) 2001 - 2009, The Board of Trustees of the University of Illinois.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the
  above copyright notice, this list of conditions
  and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the University of Illinois
  nor the names of its contributors may be used to
  endorse or promote products derived from this
  software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

/*****************************************************************************
written by
   Yunhong Gu, last updated 05/05/2009
modified by
   Haivision Systems Inc.
*****************************************************************************/

#ifndef INC_SRT_BUFFER_SND_H
#define INC_SRT_BUFFER_SND_H

#include "srt.h"
#include "packet.h"
#include "buffer_tools.h"

// The notation used for "circular numbers" in comments:
// The "cicrular numbers" are numbers that when increased up to the
// maximum become zero, and similarly, when the zero value is decreased,
// it turns into the maximum value minus one. This wrapping works the
// same for adding and subtracting. Circular numbers cannot be multiplied.

// Operations done on these numbers are marked with additional % character:
// a %> b : a is later than b
// a ++% (++%a) : shift a by 1 forward
// a +% b : shift a by b
// a == b : equality is same as for just numbers

namespace srt {

class CSndBuffer
{
    typedef sync::steady_clock::time_point time_point;
    typedef sync::steady_clock::duration   duration;

public:
    // XXX There's currently no way to access the socket ID set for
    // whatever the buffer is currently working for. Required to find
    // some way to do this, possibly by having a "reverse pointer".
    // Currently just "unimplemented".
    std::string CONID() const { return ""; }

    /// @brief CSndBuffer constructor.
    /// @param size initial number of blocks (each block to store one packet payload).
    /// @param maxpld maximum packet payload (including auth tag).
    /// @param authtag auth tag length in bytes (16 for GCM, 0 otherwise).

    // 发送缓冲区构造函数: 申请堆空间/堆空间按块划分/初始化锁
    CSndBuffer(int ip_family, int size, int maxpld, int authtag);
    ~CSndBuffer();

public:
    /// Insert a user buffer into the sending list.
    /// For @a w_mctrl the following fields are used:
    /// INPUT:
    /// - msgttl: timeout for retransmitting the message, if lost
    /// - inorder: request to deliver the message in order of sending
    /// - srctime: local time as a base for packet's timestamp (0 if unused)
    /// - pktseq: sequence number to be stamped on the packet (-1 if unused)
    /// - msgno: message number to be stamped on the packet (-1 if unused)
    /// OUTPUT:
    /// - srctime: local time stamped on the packet (same as input, if input wasn't 0)
    /// - pktseq: sequence number to be stamped on the next packet
    /// - msgno: message number stamped on the packet
    /// @param [in] data pointer to the user data block.
    /// @param [in] len size of the block.
    /// @param [inout] w_mctrl Message control data
    SRT_ATTR_EXCLUDES(m_BufLock)
    // 将数据添加到发送缓冲区
    void addBuffer(const char* data, int len, SRT_MSGCTRL& w_mctrl);

    /// Read a block of data from file and insert it into the sending list.
    /// @param [in] ifs input file stream.
    /// @param [in] len size of the block.
    /// @return actual size of data added from the file.
    SRT_ATTR_EXCLUDES(m_BufLock)
    // 从文件中读取数据，放入发送缓冲区中
    int addBufferFromFile(std::fstream& ifs, int len);

    // Special values that can be returned by readData.
    static const int READ_NONE = 0;
    static const int READ_DROP = -1;

    /// Find data position to pack a DATA packet from the furthest reading point.
    /// @param [out] packet the packet to read.
    /// @param [out] origintime origin time stamp of the message
    /// @param [in] kflags Odd|Even crypto key flag
    /// @param [out] seqnoinc the number of packets skipped due to TTL, so that seqno should be incremented.
    /// @return Actual length of data read.
    SRT_ATTR_EXCLUDES(m_BufLock)
    // 从发送缓冲区中读取数据，跳过超时的数据
    int readData(CPacket& w_packet, time_point& w_origintime, int kflgs, int& w_seqnoinc);

    /// Peek an information on the next original data packet to send.
    /// @return origin time stamp of the next packet; epoch start time otherwise.
    SRT_ATTR_EXCLUDES(m_BufLock)
    // 获取下一个要发送数据块的原始时间戳
    time_point peekNextOriginal() const;

    struct DropRange
    {
        static const size_t BEGIN = 0, END = 1;
        int32_t seqno[2];
        int32_t msgno;
    };
    /// Find data position to pack a DATA packet for a retransmission.
    /// IMPORTANT: @a packet is [in,out] because it is expected to get set
    /// the sequence number of the packet expected to be sent next. The sender
    /// buffer normally doesn't handle sequence numbers and the consistency
    /// between the sequence number of a packet already sent and kept in the
    /// buffer is achieved by having the sequence number recorded in the
    /// CUDT::m_iSndLastDataAck field that should represent the oldest packet
    /// still in the buffer.
    /// @param [in] offset offset from the last ACK point (backward sequence number difference)
    /// @param [in,out] w_packet storage for the packet, preinitialized with sequence number
    /// @param [out] w_origintime origin time stamp of the message
    /// @param [out] w_drop the drop information in case when dropping is to be done instead
    /// @retval >0 Length of the data read.
    /// @retval READ_NONE No data available or @a offset points out of the buffer occupied space.
    /// @retval READ_DROP The call requested data drop due to TTL exceeded, to be handled first.
    SRT_ATTR_EXCLUDES(m_BufLock)
    // 从发送缓冲区的指定位置开始读取数据，并检查数据块是否过期
    int readData(const int offset, CPacket& w_packet, time_point& w_origintime, DropRange& w_drop);

    /// Get the time of the last retransmission (if any) of the DATA packet.
    /// @param [in] offset offset from the last ACK point (backward sequence number difference)
    ///
    /// @return Last time of the last retransmission event for the corresponding DATA packet.
    SRT_ATTR_EXCLUDES(m_BufLock)
    // 获取指定偏移量处的数据包最后一次重传的时间戳
    time_point getPacketRexmitTime(const int offset);

    /// Update the ACK point and may release/unmap/return the user data according to the flag.
    /// @param [in] offset number of packets acknowledged.
    // 获取指定位置处数据块的消息号
    int32_t getMsgNoAt(const int offset);

    // ACK确认，从发送缓冲区中移除已被确认的数据
    void ackData(int offset);

    /// Read size of data still in the sending list.
    /// @return Current size of the data in the sending list.
    // 发送缓冲区中已使用的数据块数量
    int getCurrBufSize() const;

    SRT_ATTR_EXCLUDES(m_BufLock)
    // 丢弃过期数据包
    int dropLateData(int& bytes, int32_t& w_first_msgno, const time_point& too_late_time);

    // 更新发送缓冲区平均大小
    void updAvgBufSize(const time_point& time);
    // 获取发送缓冲区平均大小
    int  getAvgBufSize(int& bytes, int& timespan);
    // 获取发送缓冲区中已使用的数据块数量，并通过引用参数返回发送缓冲区字节数和发送缓冲区中数据的时间跨度
    int  getCurrBufSize(int& bytes, int& timespan) const;


    /// Het maximum payload length per packet.
    // 数据包最大长度，不含包头信息
    int getMaxPacketLen() const;

    /// @brief Count the number of required packets to store the payload (message).
    /// @param iPldLen the length of the payload to check.
    /// @return the number of required data packets.
    
    // 计算iPldLen长度的数据需要占用多少数据块
    int countNumPacketsRequired(int iPldLen) const;

    /// @brief Count the number of required packets to store the payload (message).
    /// @param iPldLen the length of the payload to check.
    /// @param iMaxPktLen the maximum payload length of the packet (the value returned from getMaxPacketLen()).
    /// @return the number of required data packets.
    // 计算需要iPldLen长度的数据占用多少个iMaxPktLen大小的数据块
    int countNumPacketsRequired(int iPldLen, int iMaxPktLen) const;

    /// @brief Get the buffering delay of the oldest message in the buffer.
    /// @return the delay value.
    SRT_ATTR_EXCLUDES(m_BufLock)
    // 获取缓冲区中数据的时间跨度
    duration getBufferingDelay(const time_point& tnow) const;

    // 输入码率统计的周期
    uint64_t getInRatePeriod() const { return m_rateEstimator.getInRatePeriod(); }

    /// Retrieve input bitrate in bytes per second
    // 获取输入码率：Bytes/s
    int getInputRate() const { return m_rateEstimator.getInputRate(); }
    // 重置输入码率的统计周期
    void resetInputRateSmpPeriod(bool disable = false) { m_rateEstimator.resetInputRateSmpPeriod(disable); }
    // 输入码率估算器
    const CRateEstimator& getRateEstimator() const { return m_rateEstimator; }
    // 设置输入码率估算器
    void setRateEstimator(const CRateEstimator& other) { m_rateEstimator = other; }

private:
    // 发送缓冲区扩容，每次扩容 m_iSize 个数据块大小，即(m_iSize * m_iBlockLen) 字节
    void increase();

private:
    // 发送缓冲区保护锁
    mutable sync::Mutex m_BufLock; // used to synchronize buffer operation

    // 发送缓冲区按块进行划分
    struct Block
    {
        // 数据块地址
        char* m_pcData;  // pointer to the data block
        // 数据块中有效数据的长度
        int   m_iLength; // payload length of the block (excluding auth tag).

        // 消息号，一个消息可能占用多个数据块，也可能不足一个数据块
        int32_t    m_iMsgNoBitset; // message number
        // 序列号，一个消息可能包含多个序列号
        int32_t    m_iSeqNo;       // sequence number for scheduling
        // 发送缓冲区中数据块的原始时间
        time_point m_tsOriginTime; // block origin time (either provided from above or equals the time a message was submitted for sending.
        // 重传时间
        time_point m_tsRexmitTime; // packet retransmission time
        // 生存时间
        int        m_iTTL; // time to live (milliseconds)

        Block* m_pNext; // next block

        // 获取消息号
        int32_t getMsgSeq()
        {
            // NOTE: this extracts message ID with regard to REXMIT flag.
            // This is valid only for message ID that IS GENERATED in this instance,
            // not provided by the peer. This can be otherwise sent to the peer - it doesn't matter
            // for the peer that it uses LESS bits to represent the message.
            return m_iMsgNoBitset & MSGNO_SEQ::mask;
        }

    } * m_pBlock, *m_pFirstBlock, *m_pCurrBlock, *m_pLastBlock;

    // m_pBlock:         The head pointer
    // m_pFirstBlock:    The first block
    // m_pCurrBlock:	 The current block
    // m_pLastBlock:     The last block (if first == last, buffer is empty)

    // 发送缓冲区所占用的真实物理堆空间
    struct Buffer
    {
        char*   m_pcData; // buffer
        int     m_iSize;  // size
        Buffer* m_pNext;  // next buffer
    } * m_pBuffer;        // physical buffer

    // 下一个消息号
    int32_t m_iNextMsgNo; // next message number

    // 发送缓冲区容量，单位：数据块
    int m_iSize; // buffer size (number of packets)
    // 单个数据块最大大小，包含负载和验证标签，不包含包头
    const int m_iBlockLen;  // maximum length of a block holding packet payload and AUTH tag (excluding packet header).
    // 验证标签
    const int m_iAuthTagSize; // Authentication tag size (if GCM is enabled).

    // NOTE: This is atomic AND under lock because the function getCurrBufSize()
    // is returning it WITHOUT locking. Modification, however, must stay under
    // a lock.
    // 发送缓冲区已使用的数据块数量
    sync::atomic<int> m_iCount; // number of used blocks

    // 发送队列中的字节数
    int        m_iBytesCount; // number of payload bytes in queue
    // 发送缓冲区中最后一个数据块的原始时间,即将数据放入发送缓冲区时的本地时间
    time_point m_tsLastOriginTime;

    AvgBufSize m_mavg;
    // 带宽码率估算
    CRateEstimator m_rateEstimator;

private:
    CSndBuffer(const CSndBuffer&);
    CSndBuffer& operator=(const CSndBuffer&);
};

} // namespace srt

#endif
