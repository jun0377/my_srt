/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

#include <string>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <utility>
#include <memory>

#include "statswriter.hpp"
#include "netinet_any.h"
#include "srt_compat.h"


using namespace std;


template <class TYPE>
inline SrtStatData* make_stat(SrtStatCat cat, const string& name, const string& longname,
        TYPE CBytePerfMon::*field)
{
    return new SrtStatDataType<TYPE>(cat, name, longname, field);
}

#define STATX(catsuf, sname, lname, field) s.emplace_back(make_stat(SSC_##catsuf, #sname, #lname, &CBytePerfMon:: field))
#define STAT(catsuf, sname, field) STATX(catsuf, sname, field, field)

vector<unique_ptr<SrtStatData>> g_SrtStatsTable;

// 统计表，记录了需要统计的参数
struct SrtStatsTableInit
{
    SrtStatsTableInit(vector<unique_ptr<SrtStatData>>& s)
    {
        STATX(GEN, time, Time, msTimeStamp);

        STAT(WINDOW, flow, pktFlowWindow);
        STAT(WINDOW, congestion, pktCongestionWindow);
        STAT(WINDOW, flight, pktFlightSize);

        STAT(LINK, rtt, msRTT);
        STAT(LINK, bandwidth, mbpsBandwidth);
        STAT(LINK, maxBandwidth, mbpsMaxBW);

        STAT(SEND, packets, pktSent);
        STAT(SEND, packetsUnique, pktSentUnique);
        STAT(SEND, packetsLost, pktSndLoss);
        STAT(SEND, packetsDropped, pktSndDrop);
        STAT(SEND, packetsRetransmitted, pktRetrans);
        STAT(SEND, packetsFilterExtra, pktSndFilterExtra);
        STAT(SEND, bytes, byteSent);
        STAT(SEND, bytesUnique, byteSentUnique);
        STAT(SEND, bytesDropped, byteSndDrop);
        STAT(SEND, byteAvailBuf, byteAvailSndBuf);
        STAT(SEND, msBuf, msSndBuf);
        STAT(SEND, mbitRate, mbpsSendRate);
        STAT(SEND, sendPeriod, usPktSndPeriod);

        STAT(RECV, packets, pktRecv);
        STAT(RECV, packetsUnique, pktRecvUnique);
        STAT(RECV, packetsLost, pktRcvLoss);
        STAT(RECV, packetsDropped, pktRcvDrop);
        STAT(RECV, packetsRetransmitted, pktRcvRetrans);
        STAT(RECV, packetsBelated, pktRcvBelated);
        STAT(RECV, packetsFilterExtra, pktRcvFilterExtra);
        STAT(RECV, packetsFilterSupply, pktRcvFilterSupply);
        STAT(RECV, packetsFilterLoss, pktRcvFilterLoss);
        STAT(RECV, bytes, byteRecv);
        STAT(RECV, bytesUnique, byteRecvUnique);
        STAT(RECV, bytesLost, byteRcvLoss);
        STAT(RECV, bytesDropped, byteRcvDrop);
        STAT(RECV, byteAvailBuf, byteAvailRcvBuf);
        STAT(RECV, msBuf, msRcvBuf);
        STAT(RECV, mbitRate, mbpsRecvRate);
        STAT(RECV, msTsbPdDelay, msRcvTsbPdDelay);
    }
} g_SrtStatsTableInit (g_SrtStatsTable);


#undef STAT
#undef STATX

// 状态信息分类，enum SrtStatCat枚举类型中五种分类对应的字符串
string srt_json_cat_names [] = {
    "",
    "window",
    "link",
    "send",
    "recv"
};

#ifdef HAVE_CXX_STD_PUT_TIME
// Follows ISO 8601
// 输出时间戳
std::string SrtStatsWriter::print_timestamp()
{
    using namespace std;
    using namespace std::chrono;

    const auto   systime_now = system_clock::now();
    const time_t time_now    = system_clock::to_time_t(systime_now);

    std::ostringstream output;

    // SysLocalTime returns zeroed tm_now on failure, which is ok for put_time.
    // 失败时返回一个全是0的tm_now结构体
    const tm tm_now = SysLocalTime(time_now);
    // 格式化日期和时间
    output << std::put_time(&tm_now, "%FT%T.") << std::setfill('0') << std::setw(6);
    // 获取自纪元以来的时间
    const auto    since_epoch = systime_now.time_since_epoch();
    // 纪元时间转换成秒
    const seconds s           = duration_cast<seconds>(since_epoch);
    // 时间的微秒部分
    output << duration_cast<microseconds>(since_epoch - s).count();
    // 输出时区
    output << std::put_time(&tm_now, "%z");
    return output.str();
}
#else

// This is a stub. The error when not defining it would be too
// misleading, so this stub will work if someone mistakenly adds
// the item to the output format without checking that HAVE_CXX_STD_PUT_TIME
string SrtStatsWriter::print_timestamp()
{ return "<NOT IMPLEMENTED>"; }
#endif // HAVE_CXX_STD_PUT_TIME

// 抽象工厂模式的具体实现类 - JSON格式的状态信息
class SrtStatsJson : public SrtStatsWriter
{
    // 给键名添加引号和冒号
    static string quotekey(const string& name)
    {
        if (name == "")
            return "";

        return R"(")" + name + R"(":)";
    }

    // 给值增加引号
    static string quote(const string& name)
    {
        if (name == "")
            return "";

        return R"(")" + name + R"(")";
    }

public: 
    // 重写基类中的状态记录函数，写入JSON格式的状态信息
    string WriteStats(int sid, const CBytePerfMon& mon) override
    {
        std::ostringstream output;

        string pretty_cr, pretty_tab;

        // 如果设置了pretty美化选项，则使用换行和缩进来格式化输出
        if (Option("pretty"))
        {
            pretty_cr = "\n";
            pretty_tab = "\t";
        }

        // 初始化状态信息分类为通用类
        SrtStatCat cat = SSC_GEN;

        // Do general manually
        // 开始一个JSON对象
        output << quotekey(srt_json_cat_names[cat]) << "{" << pretty_cr;

        // SID is displayed manually
        // 向JSON对象中添加sid，SocketID
        output << pretty_tab << quotekey("sid") << sid;

        // Extra Timepoint is also displayed manually
#ifdef HAVE_CXX_STD_PUT_TIME
        // NOTE: still assumed SSC_GEN category

        // 向JSON对象中添加时间戳
        output << "," << pretty_cr << pretty_tab
            << quotekey("timepoint") << quote(print_timestamp());
#endif

        // Now continue with fields as specified in the table
        // 遍历统计表中需要记录的统计参数,添加到JSON对象中
        for (auto& i: g_SrtStatsTable)
        {
            if (i->category == cat)
            {
                output << ","; // next item in same cat
                output << pretty_cr;
                output << pretty_tab;
                if (cat != SSC_GEN)
                    output << pretty_tab;
            }
            else
            {
                if (cat != SSC_GEN)
                {
                    // DO NOT close if general category, just
                    // enter the depth.
                    output << pretty_cr << pretty_tab << "}";
                }
                cat = i->category;
                output << ",";
                output << pretty_cr;
                if (cat != SSC_GEN)
                    output << pretty_tab;

                output << quotekey(srt_json_cat_names[cat]) << "{" << pretty_cr << pretty_tab;
                if (cat != SSC_GEN)
                    output << pretty_tab;
            }

            // Print the current field
            output << quotekey(i->name);
            i->PrintValue(output, mon);
        }

        // Close the previous subcategory
        // 关闭上一个状态信息分类
        if (cat != SSC_GEN)
        {
            output << pretty_cr << pretty_tab << "}" << pretty_cr;
        }

        // Close the general category entity
        output << "}" << pretty_cr << endl;

        return output.str();
    }

    // 重写基类中的带宽记录函数，写入JSON格式的带宽信息
    string WriteBandwidth(double mbpsBandwidth) override
    {
        std::ostringstream output;
        output << "{\"bandwidth\":" << mbpsBandwidth << '}' << endl;
        return output.str();
    }
};

class SrtStatsCsv : public SrtStatsWriter
{
private:
    bool first_line_printed;

public: 
    SrtStatsCsv() : first_line_printed(false) {}

    string WriteStats(int sid, const CBytePerfMon& mon) override
    {
        std::ostringstream output;

        // Header
        if (!first_line_printed)
        {
#ifdef HAVE_CXX_STD_PUT_TIME
            output << "Timepoint,";
#endif
            output << "Time,SocketID";

            for (auto& i: g_SrtStatsTable)
            {
                output << "," << i->longname;
            }
            output << endl;
            first_line_printed = true;
        }

        // Values
#ifdef HAVE_CXX_STD_PUT_TIME
        // HDR: Timepoint
        output << print_timestamp() << ",";
#endif // HAVE_CXX_STD_PUT_TIME

        // HDR: Time,SocketID
        output << mon.msTimeStamp << "," << sid;

        // HDR: the loop of all values in g_SrtStatsTable
        for (auto& i: g_SrtStatsTable)
        {
            output << ",";
            i->PrintValue(output, mon);
        }

        output << endl;
        return output.str();
    }

    string WriteBandwidth(double mbpsBandwidth) override
    {
        std::ostringstream output;
        output << "+++/+++SRT BANDWIDTH: " << mbpsBandwidth << endl;
        return output.str();
    }
};

class SrtStatsCols : public SrtStatsWriter
{
public: 
    string WriteStats(int sid, const CBytePerfMon& mon) override 
    { 
        std::ostringstream output;
        output << "======= SRT STATS: sid=" << sid << endl;
        output << "PACKETS     SENT: " << setw(11) << mon.pktSent            << "  RECEIVED:   " << setw(11) << mon.pktRecv              << endl;
        output << "LOST PKT    SENT: " << setw(11) << mon.pktSndLoss         << "  RECEIVED:   " << setw(11) << mon.pktRcvLoss           << endl;
        output << "REXMIT      SENT: " << setw(11) << mon.pktRetrans         << "  RECEIVED:   " << setw(11) << mon.pktRcvRetrans        << endl;
        output << "DROP PKT    SENT: " << setw(11) << mon.pktSndDrop         << "  RECEIVED:   " << setw(11) << mon.pktRcvDrop           << endl;
        output << "FILTER EXTRA  TX: " << setw(11) << mon.pktSndFilterExtra  << "        RX:   " << setw(11) << mon.pktRcvFilterExtra    << endl;
        output << "FILTER RX  SUPPL: " << setw(11) << mon.pktRcvFilterSupply << "  RX  LOSS:   " << setw(11) << mon.pktRcvFilterLoss     << endl;
        output << "RATE     SENDING: " << setw(11) << mon.mbpsSendRate       << "  RECEIVING:  " << setw(11) << mon.mbpsRecvRate         << endl;
        output << "BELATED RECEIVED: " << setw(11) << mon.pktRcvBelated      << "  AVG TIME:   " << setw(11) << mon.pktRcvAvgBelatedTime << endl;
        output << "REORDER DISTANCE: " << setw(11) << mon.pktReorderDistance << endl;
        output << "WINDOW      FLOW: " << setw(11) << mon.pktFlowWindow      << "  CONGESTION: " << setw(11) << mon.pktCongestionWindow  << "  FLIGHT: " << setw(11) << mon.pktFlightSize << endl;
        output << "LINK         RTT: " << setw(9)  << mon.msRTT            << "ms  BANDWIDTH:  " << setw(7)  << mon.mbpsBandwidth    << "Mb/s " << endl;
        output << "BUFFERLEFT:  SND: " << setw(11) << mon.byteAvailSndBuf    << "  RCV:        " << setw(11) << mon.byteAvailRcvBuf      << endl;
        return output.str();
    } 

    string WriteBandwidth(double mbpsBandwidth) override 
    {
        std::ostringstream output;
        output << "+++/+++SRT BANDWIDTH: " << mbpsBandwidth << endl;
        return output.str();
    }
};

// 工厂函数，用于创建不同格式的统计信息写入器;比如 JSON/CSV/2列 这三种格式
shared_ptr<SrtStatsWriter> SrtStatsWriterFactory(SrtStatsPrintFormat printformat)
{
    switch (printformat)
    {
    // JSON格式
    case SRTSTATS_PROFMAT_JSON:
        return make_shared<SrtStatsJson>();
    // CSV格式
    case SRTSTATS_PROFMAT_CSV:
        return make_shared<SrtStatsCsv>();
    // 两列格式
    case SRTSTATS_PROFMAT_2COLS:
        return make_shared<SrtStatsCols>();
    default:
        break;
    }
    return nullptr;
}

SrtStatsPrintFormat ParsePrintFormat(string pf, string& w_extras)
{
    size_t havecomma = pf.find(',');
    if (havecomma != string::npos)
    {
        w_extras = pf.substr(havecomma+1);
        pf = pf.substr(0, havecomma);
    }

    if (pf == "default")
        return SRTSTATS_PROFMAT_2COLS;

    if (pf == "json")
        return SRTSTATS_PROFMAT_JSON;

    if (pf == "csv")
        return SRTSTATS_PROFMAT_CSV;

    return SRTSTATS_PROFMAT_INVALID;
}