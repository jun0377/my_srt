/*
 * SRT - Secure Reliable Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

/*****************************************************************************
Copyright (c) 2001 - 2011, The Board of Trustees of the University of Illinois.
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
   Yunhong Gu, last updated 01/02/2011
modified by
   Haivision Systems Inc.
*****************************************************************************/

#ifndef INC_SRT_PACKET_H
#define INC_SRT_PACKET_H

#include "udt.h"
#include "common.h"
#include "utilities.h"
#include "netinet_any.h"
#include "packetfilter_api.h"

namespace srt
{

//////////////////////////////////////////////////////////////////////////////
// The purpose of the IOVector class is to proide a platform-independet interface
// to the WSABUF on Windows and iovec on Linux, that can be easilly converted
// to the native structure for use in WSARecvFrom() and recvmsg(...) functions
class IOVector
#ifdef _WIN32
    : public WSABUF
#else
    : public iovec
#endif
{
public:
    IOVector() { set(NULL, 0); }

    inline void set(void* buffer, size_t length)
    {
#ifdef _WIN32
        len = (ULONG)length;
        buf = (CHAR*)buffer;
#else
        iov_base = (void*)buffer;
        iov_len  = length;
#endif
    }

    inline char*& dataRef()
    {
#ifdef _WIN32
        return buf;
#else
        return (char*&)iov_base;
#endif
    }

    inline char* data()
    {
#ifdef _WIN32
        return buf;
#else
        return (char*)iov_base;
#endif
    }

    inline size_t size() const
    {
#ifdef _WIN32
        return (size_t)len;
#else
        return iov_len;
#endif
    }

    inline void setLength(size_t length)
    {
#ifdef _WIN32
        len = (ULONG)length;
#else
        iov_len = length;
#endif
    }
};

/// To define packets in order in the buffer. This is public due to being used in buffer.
enum PacketBoundary
{
    // 当前消息的中间数据块
    PB_SUBSEQUENT = 0, // 00: a packet in the middle of a message, neither the first, not the last.
    // 当前消息的最后一个数据块
    PB_LAST       = 1, // 01: last packet of a message
    // 当前消息的第一个数据块
    PB_FIRST      = 2, // 10: first packet of a message
    // 当前消息只有一个数据块
    PB_SOLO       = 3, // 11: solo message packet
};

// Breakdown of the PM_SEQNO field in the header:
//  C| X X ... X, where:
typedef Bits<31> SEQNO_CONTROL;
//  1|T T T T T T T T T T T T T T T|E E...E
typedef Bits<30, 16> SEQNO_MSGTYPE;
typedef Bits<15, 0>  SEQNO_EXTTYPE;
//  0|S S ... S
typedef Bits<30, 0> SEQNO_VALUE;

// This bit cannot be used by SEQNO anyway, so it's additionally used
// in LOSSREPORT data specification to define that this value is the
// BEGIN value for a SEQNO range (to distinguish it from a SOLO loss SEQNO value).
const int32_t LOSSDATA_SEQNO_RANGE_FIRST = SEQNO_CONTROL::mask;

// Just cosmetics for readability.
const int32_t LOSSDATA_SEQNO_RANGE_LAST = 0, LOSSDATA_SEQNO_SOLO = 0;

inline int32_t CreateControlSeqNo(UDTMessageType type)
{
    return SEQNO_CONTROL::mask | SEQNO_MSGTYPE::wrap(uint32_t(type));
}

inline int32_t CreateControlExtSeqNo(int exttype)
{
    return SEQNO_CONTROL::mask | SEQNO_MSGTYPE::wrap(size_t(UMSG_EXT)) | SEQNO_EXTTYPE::wrap(exttype);
}

// MSGNO breakdown: B B|O|K K|R|M M M M M M M M M M...M
typedef Bits<31, 30> MSGNO_PACKET_BOUNDARY;
typedef Bits<29>     MSGNO_PACKET_INORDER;
typedef Bits<28, 27> MSGNO_ENCKEYSPEC;
#if 1 // can block rexmit flag
// New bit breakdown - rexmit flag supported.
typedef Bits<26>    MSGNO_REXMIT;
typedef Bits<25, 0> MSGNO_SEQ;
// Old bit breakdown - no rexmit flag
typedef Bits<26, 0> MSGNO_SEQ_OLD;
// This symbol is for older SRT version, where the peer does not support the MSGNO_REXMIT flag.
// The message should be extracted as PMASK_MSGNO_SEQ, if REXMIT is supported, and PMASK_MSGNO_SEQ_OLD otherwise.

const uint32_t PACKET_SND_NORMAL = 0, PACKET_SND_REXMIT = MSGNO_REXMIT::mask;
const int      MSGNO_SEQ_MAX = MSGNO_SEQ::mask;

#else
// Old bit breakdown - no rexmit flag
typedef Bits<26, 0> MSGNO_SEQ;
#endif

typedef RollNumber<MSGNO_SEQ::size - 1, 1> MsgNo;

// constexpr in C++11 !
inline int32_t PacketBoundaryBits(PacketBoundary o)
{
    return MSGNO_PACKET_BOUNDARY::wrap(int32_t(o));
}

enum EncryptionKeySpec
{
    EK_NOENC = 0,
    EK_EVEN  = 1,
    EK_ODD   = 2
};

enum EncryptionStatus
{
    ENCS_CLEAR  = 0,
    ENCS_FAILED = -1,
    ENCS_NOTSUP = -2
};

const int32_t  PMASK_MSGNO_ENCKEYSPEC = MSGNO_ENCKEYSPEC::mask;
inline int32_t EncryptionKeyBits(EncryptionKeySpec f)
{
    return MSGNO_ENCKEYSPEC::wrap(int32_t(f));
}
inline EncryptionKeySpec GetEncryptionKeySpec(int32_t msgno)
{
    return EncryptionKeySpec(MSGNO_ENCKEYSPEC::unwrap(msgno));
}

const int32_t PUMASK_SEQNO_PROBE = 0xF;

std::string PacketMessageFlagStr(uint32_t msgno_field);

// 数据包结构
class CPacket
{
    friend class CChannel;
    friend class CSndQueue;
    friend class CRcvQueue;

public:
    CPacket();
    ~CPacket();

    // 为数据域分配堆空间
    void allocate(size_t size);
    // 释放数据域堆空间
    void deallocate();

    /// Get the payload or the control information field length.
    /// @return the payload or the control information field length.

    // 获取数据域有效数据长度
    size_t getLength() const;

    /// Set the payload or the control information field length.
    /// @param len [in] the payload or the control information field length.

    // 设置数据域有效数据长度
    void setLength(size_t len);

    /// Set the payload or the control information field length.
    /// @param len [in] the payload or the control information field length.
    /// @param cap [in] capacity (if known).
    
    // 设置数据域有效数据长度和容量
    void setLength(size_t len, size_t cap);

    /// Pack a Control packet.
    /// @param pkttype [in] packet type filed.
    /// @param lparam [in] pointer to the first data structure, explained by the packet type.
    /// @param rparam [in] pointer to the second data structure, explained by the packet type.
    /// @param size [in] size of rparam, in number of bytes;

    // 控制包打包
    void pack(UDTMessageType pkttype, const int32_t* lparam = NULL, void* rparam = NULL, size_t size = 0);

    /// Read the packet vector.
    /// @return Pointer to the packet vector.

    // 获取数据包指针
    IOVector* getPacketVector();

    // 获取包头
    uint32_t* getHeader() { return m_nHeader; }

    /// Read the packet type.
    /// @return packet type filed (000 ~ 111).
    
    // 获取数据包类型
    UDTMessageType getType() const;

    // 是否是一个指定类型的控制包
    bool isControl(UDTMessageType type) const { return isControl() && type == getType(); }

    // 是否是一个控制包
    bool isControl() const { return 0 != SEQNO_CONTROL::unwrap(m_nHeader[SRT_PH_SEQNO]); }

    // 设置包类型
    void setControl(UDTMessageType type) { m_nHeader[SRT_PH_SEQNO] = SEQNO_CONTROL::mask | SEQNO_MSGTYPE::wrap(type); }

    /// Read the extended packet type.
    /// @return extended packet type filed (0x000 ~ 0xFFF).

    // 获取扩展类型,bit[15:0]
    int getExtendedType() const;

    /// Read the ACK-2 seq. no.
    /// @return packet header field (bit 16~31).

    // 获取ACK-2序列号，其实就是获取包的消息号
    int32_t getAckSeqNo() const;

    // 获取控制包的扩展类型
    uint16_t getControlFlags() const;

    // Note: this will return a "singular" value, if the packet
    // contains the control message

    // 获取序列号
    int32_t getSeqNo() const { return m_nHeader[SRT_PH_SEQNO]; }

    /// Read the message boundary flag bit.
    /// @return packet header field [1] (bit 0~1).
    
    // 获取消息边界
    PacketBoundary getMsgBoundary() const;

    /// Read the message inorder delivery flag bit.
    /// @return packet header field [1] (bit 2).

    // 获取乱序标识
    bool getMsgOrderFlag() const;

    /// Read the rexmit flag (true if the packet was sent due to retransmission).
    /// If the peer does not support retransmission flag, the current agent cannot use it as well
    /// (because the peer will understand this bit as a part of MSGNO field).

    // 获取重传标识，true说明是一个重传的包
    bool getRexmitFlag() const;

    // 设置重传标识
    void setRexmitFlag(bool bRexmit);

    /// Read the message sequence number.
    /// @return packet header field [1]

    // 获取消息号
    int32_t getMsgSeq(bool has_rexmit = true) const;

    /// Read the message crypto key bits.
    /// @return packet header field [1] (bit 3~4).

    // 获取消息加密密钥
    EncryptionKeySpec getMsgCryptoFlags() const;

    // 设置消息加密密钥
    void setMsgCryptoFlags(EncryptionKeySpec spec);

    /// Read the message time stamp.
    /// @return packet header field [2] (bit 0~31, bit 0-26 if SRT_DEBUG_TSBPD_WRAP).

    // 获取消息时间戳
    uint32_t getMsgTimeStamp() const;

    // UDP目的地址
    sockaddr_any udpDestAddr() const { return m_DestAddr; }

#ifdef SRT_DEBUG_TSBPD_WRAP                           // Receiver
    // 时间戳最大值
    static const uint32_t MAX_TIMESTAMP = 0x07FFFFFF; // 27 bit fast wraparound for tests (~2m15s)
#else
    static const uint32_t MAX_TIMESTAMP = 0xFFFFFFFF; // Full 32 bit (01h11m35s)
#endif

protected:
    // 时间戳掩码
    static const uint32_t TIMESTAMP_MASK = MAX_TIMESTAMP; // this value to be also used as a mask
public:
    /// Clone this packet.
    /// @return Pointer to the new packet.

    // 克隆一个数据包
    CPacket* clone() const;

    // 数据包字段; 0 - 包头字段; 1 - 数据字段;
    enum PacketVectorFields
    {
        PV_HEADER = 0,
        PV_DATA   = 1,

        PV_SIZE = 2
    };

public:
    /// @brief Convert the packet inline to a network byte order (Little-endian).
    // 转换为网络字节序
    // 控制包的负载部分需要转换成网络字节序; 数据包的负载部分不必进行转换; 数据的解释是应用层的责任
    void toNetworkByteOrder();
	/// @brief Convert the packet inline to a host byte order.
    // 转换成本地字节序
    // 控制包的负载部分需要转换成本地字节序; 数据包的负载部分不必进行转换
    void toHostByteOrder();

protected:
    // DynamicStruct is the same as array of given type and size, just it
    // enforces that you index it using a symbol from symbolic enum type, not by a bare integer.

    typedef DynamicStruct<uint32_t, SRT_PH_E_SIZE, SrtPktHeaderFields> HEADER_TYPE;
    // 128bit的包头
    HEADER_TYPE                                                        m_nHeader; //< The 128-bit header field

    // m_PacketVector[0] - 包头; m_PacketVector[1] - 数据
    IOVector m_PacketVector[PV_SIZE]; //< The two-dimensional vector of an SRT packet [header, data]

    // 扩展
    int32_t m_extra_pad;
    // 是否拥有数据域的所有权，负责管理数据域的堆空间
    bool    m_data_owned;
    sockaddr_any m_DestAddr;
    // 数据包容量
    size_t  m_zCapacity;

protected:
    CPacket& operator=(const CPacket&);
    CPacket(const CPacket&);

public:
    // 指针，指向控制包的包头部分; 指向数据包的数据部分
    char*&   m_pcData;     // alias: payload (data packet) / control information fields (control packet)

    // 只写属性
    SRTU_PROPERTY_WO_ARG(SRTSOCKET, id, m_nHeader[SRT_PH_ID] = int32_t(arg));
    // 只读属性
    SRTU_PROPERTY_RO(SRTSOCKET, id, SRTSOCKET(m_nHeader[SRT_PH_ID]));

    // 读写属性
    SRTU_PROPERTY_RW(int32_t, seqno, m_nHeader[SRT_PH_SEQNO]);
    SRTU_PROPERTY_RW(int32_t, msgflags, m_nHeader[SRT_PH_MSGNO]);
    SRTU_PROPERTY_RW(int32_t, timestamp, m_nHeader[SRT_PH_TIMESTAMP]);

    // Experimental: sometimes these references don't work!
    // 获取数据域
    char* getData();
    // 释放数据域堆空间
    char* release();

    // 包头大小: 目前固定为128bit，采用sizeof计算是为了兼容将来可能对包头进行扩展
    static const size_t HDR_SIZE = sizeof(HEADER_TYPE); // packet header size = SRT_PH_E_SIZE * sizeof(uint32_t)

    // Can also be calculated as: sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr).
    static const size_t UDP_HDR_SIZE = 28; // 20 bytes IPv4 + 8 bytes of UDP { u16 sport, dport, len, csum }.

    static const size_t SRT_DATA_HDR_SIZE = UDP_HDR_SIZE + HDR_SIZE;

    // Maximum transmission unit size. 1500 in case of Ethernet II (RFC 1191).
    static const size_t ETH_MAX_MTU_SIZE = 1500;

    // Maximum payload size of an SRT packet.
    static const size_t SRT_MAX_PAYLOAD_SIZE = ETH_MAX_MTU_SIZE - SRT_DATA_HDR_SIZE;

    // Packet interface
    // 获取数据包的数据，获取控制包的包头
    char*       data() { return m_pcData; }
    const char* data() const { return m_pcData; }
    // 负载长度
    size_t      size() const { return getLength(); }
    // 数据包容量
    size_t      capacity() const { return m_zCapacity; }
    // 设置数据包容量
    void        setCapacity(size_t cap) { m_zCapacity = cap; }
    // 获取包头中的指定域
    uint32_t    header(SrtPktHeaderFields field) const { return m_nHeader[field]; }

#if ENABLE_LOGGING
    // 调试信息，以字符串形式输出消息标识
    std::string MessageFlagStr() { return PacketMessageFlagStr(m_nHeader[SRT_PH_MSGNO]); }
    std::string Info();
#else
    std::string           MessageFlagStr() { return std::string(); }
    std::string           Info() { return std::string(); }
#endif
};

} // namespace srt

#endif
