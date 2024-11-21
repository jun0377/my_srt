/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */


#ifndef INC_SRT_APPS_STATSWRITER_H
#define INC_SRT_APPS_STATSWRITER_H

#include <string>
#include <map>
#include <vector>
#include <memory>

#include "srt.h"
#include "utilities.h"

// 状态信息输出格式
enum SrtStatsPrintFormat
{
    SRTSTATS_PROFMAT_INVALID = -1,      // 无效格式
    SRTSTATS_PROFMAT_2COLS = 0,         // 2列格式
    SRTSTATS_PROFMAT_JSON,              // JSON格式
    SRTSTATS_PROFMAT_CSV                // CSV格式
};

SrtStatsPrintFormat ParsePrintFormat(std::string pf, std::string& w_extras);

// 状态信息分类
enum SrtStatCat
{
    SSC_GEN, //< General，通用
    SSC_WINDOW, // flow/congestion window，流/拥塞窗口
    SSC_LINK, //< Link data，链路数据
    SSC_SEND, //< Sending，发送
    SSC_RECV //< Receiving，接收
};

// 状态信息 - 抽象类
struct SrtStatData
{
    // 分类
    SrtStatCat category;
    // 名称
    std::string name;
    // 详细名称
    std::string longname;

    SrtStatData(SrtStatCat cat, std::string n, std::string l): category(cat), name(n), longname(l) {}
    virtual ~SrtStatData() {}

    virtual void PrintValue(std::ostream& str, const CBytePerfMon& mon) = 0;
};

/*
    泛型统计数据类型，用于处理CBytePerfMon中不同类型的统计字段
*/
template <class TYPE>
struct SrtStatDataType: public SrtStatData
{
    // 泛型编程，pfield_t是指向CBytePerfMon结构体中某个成员的指针类型
    typedef TYPE CBytePerfMon::*pfield_t;
    pfield_t pfield;

    SrtStatDataType(SrtStatCat cat, const std::string& name, const std::string& longname, pfield_t field)
        : SrtStatData (cat, name, longname), pfield(field)
    {
    }

    // 输出CBytePerfMon中的某个参数
    void PrintValue(std::ostream& str, const CBytePerfMon& mon) override
    {
        str << mon.*pfield;
    }
};

// 抽象工厂模式 - 抽象基类，状态信息写入器
class SrtStatsWriter
{
public:
    // 纯虚函数，用于写于状态信息
    virtual std::string WriteStats(int sid, const CBytePerfMon& mon) = 0;
    // 纯虚函数，用于写于带宽信息
    virtual std::string WriteBandwidth(double mbpsBandwidth) = 0;
    // 虚析构
    virtual ~SrtStatsWriter() {}

    // Only if HAS_PUT_TIME. Specified in the imp file.
    // 输出时间戳
    std::string print_timestamp();

    // 设置选项
    void Option(const std::string& key, const std::string& val)
    {
        options[key] = val;
    }

    // 获取选项
    bool Option(const std::string& key, std::string* rval = nullptr)
    {
        const std::string* out = map_getp(options, key);
        if (!out)
            return false;

        if (rval)
            *rval = *out;
        return true;
    }

protected:
    std::map<std::string, std::string> options;
};

extern std::vector<std::unique_ptr<SrtStatData>> g_SrtStatsTable;

std::shared_ptr<SrtStatsWriter> SrtStatsWriterFactory(SrtStatsPrintFormat printformat);



#endif
