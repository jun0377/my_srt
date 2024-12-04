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
Copyright (c) 2001 - 2010, The Board of Trustees of the University of Illinois.
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
   Yunhong Gu, last updated 08/20/2010
modified by
   Haivision Systems Inc.
*****************************************************************************/

#ifndef INC_SRT_EPOLL_H
#define INC_SRT_EPOLL_H


#include <map>
#include <set>
#include <list>
#include "udt.h"

namespace srt
{

class CUDT;
class CRendezvousQueue;
class CUDTGroup;


/*
	描述一个EPOLL实例,包含: 
		epoll实例ID
		epoll实例相关的所有SRTSOCKET和SYSSOCKET
			- 
		触发的事件Notice
			- 添加一个触发事件Notice
			- 更新一个触发事件Notice
			- 删除一个触发事件Notice
			- 清除所有已触发的事件
		关注的事件Wait 
			- 添加SOCKET需要关注的事件
			- 清除指定SOCKET关注的事件
			- 清除所有关注的事件
*/
class CEPollDesc
{

	// epoll实例ID
#ifdef __GNUG__
   const int m_iID;                                // epoll ID
#else
   const int m_iID SRT_ATR_UNUSED;                 // epoll ID
#endif
   struct Wait;

	// 事件通知，记录对应事件和对应的SRTSOCKET
   struct Notice: public SRT_EPOLL_EVENT
   {
       Wait* parent;

       Notice(Wait* p, SRTSOCKET sock, int ev): parent(p)
       {
           fd = sock;
           events = ev;
       }
   };

   /// The type for `m_USockEventNotice`, the pair contains:
   /// * The back-pointer to the subscriber object for which this event notice serves
   /// * The events currently being on
   typedef std::list<Notice> enotice_t;

	// epoll事件，包含关注的事件/触发的事件/事件清除等功能
   struct Wait
   {
       /// Events the subscriber is interested with. Only those will be
       /// regarded when updating event flags.

	   // 订阅的事件
       int32_t watch;

       /// Which events should be edge-triggered. When the event isn't
       /// mentioned in `watch`, this bit flag is disregarded. Otherwise
       /// it means that the event is to be waited for persistent state
       /// if this flag is not present here, and for edge trigger, if
       /// the flag is present here.

	   // 订阅的边缘触发事件
       int32_t edge;

       /// The current persistent state. This is usually duplicated in
       /// a dedicated state object in `m_USockEventNotice`, however the state
       /// here will stay forever as is, regardless of the edge/persistent
       /// subscription mode for the event.

	   // 订阅事件的状态，已触发还没有通知用户的事件
       int32_t state;

       /// The iterator to `m_USockEventNotice` container that contains the
       /// event notice object for this subscription, or the value from
       /// `nullNotice()` if there is no such object.

	   // 通知事件，即触发的事件
       enotice_t::iterator notit;

        // 构造函数
       Wait(explicit_t<int32_t> sub, explicit_t<int32_t> etr, enotice_t::iterator i)
           :watch(sub)
           ,edge(etr)
           ,state(0)
           ,notit(i)
       {
       }

        // 返回边缘触发的事件
       int edgeOnly() { return edge & watch; }

       /// Clear all flags for given direction from the notices
       /// and subscriptions, and checks if this made the event list
       /// for this watch completely empty.
       /// @param direction event type that has to be cleared
       /// @return true, if this cleared the last event (the caller
       /// want to remove the subscription for this socket)

       // 清除给定方向的事件
       bool clear(int32_t direction)
       {
           if (watch & direction)
           {
               watch &= ~direction;
               edge &= ~direction;
               state &= ~direction;

               return watch == 0;
           }

           return false;
       }
   };

   typedef std::map<SRTSOCKET, Wait> ewatch_t;

#if ENABLE_HEAVY_LOGGING
std::string DisplayEpollWatch();
#endif

   /// Sockets that are subscribed for events in this eid.
   // 事件订阅管理，使用一个map来维护所有事件及对应的SRTSOCKET
   ewatch_t m_USockWatchState;

   /// Objects representing changes in SRT sockets.
   /// Objects are removed from here when an event is registerred as edge-triggered.
   /// Otherwise it is removed only when all events as per subscription
   /// are no longer on.

   // 事件list, 使用一个list来记录所有已触发的事件和对应的SRTSOCKET
   enotice_t m_USockEventNotice;

   // Special behavior
   int32_t m_Flags;

    // 事件迭代器
   enotice_t::iterator nullNotice() { return m_USockEventNotice.end(); }

   // Only CEPoll class should have access to it.
   // Guarding private access to the class is not necessary
   // within the epoll module.
   friend class CEPoll;

   CEPollDesc(int id, int localID)
       : m_iID(id)
       , m_Flags(0)
       , m_iLocalID(localID)
    {
    }

   static const int32_t EF_NOCHECK_EMPTY = 1 << 0;
   static const int32_t EF_CHECK_REP = 1 << 1;

   // 获取flags
   int32_t flags() const { return m_Flags; }
   // 设置flags
   bool flags(int32_t f) const { return (m_Flags & f) != 0; }
   // flags置位
   void set_flags(int32_t flg) { m_Flags |= flg; }
   // flags位清零
   void clr_flags(int32_t flg) { m_Flags &= ~flg; }

   // Container accessors for ewatch_t.

   // 关注的事件是否空，即没有订阅的事件
   bool watch_empty() const { return m_USockWatchState.empty(); }
   // 获取指定SRTSOCKET的关注事件
   Wait* watch_find(SRTSOCKET sock)
   {
        // 从map中查找
       ewatch_t::iterator i = m_USockWatchState.find(sock);
       if (i == m_USockWatchState.end())
           return NULL;
       return &i->second;
   }

   // Container accessors for enotice_t.

   // 已触发事件起始迭代器
   enotice_t::iterator enotice_begin() { return m_USockEventNotice.begin(); }
   // 已触发事件终止迭代器
   enotice_t::iterator enotice_end() { return m_USockEventNotice.end(); }
   // 已触发事件的常量起始迭代器
   enotice_t::const_iterator enotice_begin() const { return m_USockEventNotice.begin(); }
   // 已触发事件的常量终止迭代器
   enotice_t::const_iterator enotice_end() const { return m_USockEventNotice.end(); }
   // 触发事件列表是否为空
   bool enotice_empty() const { return m_USockEventNotice.empty(); }

    // 系统epoll实例
   const int m_iLocalID;                           // local system epoll ID
   // 系统套接字集合
   std::set<SYSSOCKET> m_sLocals;            // set of local (non-UDT) descriptors

    // 添加需要关注的事件
   std::pair<ewatch_t::iterator, bool> addWatch(SRTSOCKET sock, explicit_t<int32_t> events, explicit_t<int32_t> et_events)
   {
        // 插入到map中
        return m_USockWatchState.insert(std::make_pair(sock, Wait(events, et_events, nullNotice())));
   }

    // 添加触发的事件，事件通知
   void addEventNotice(Wait& wait, SRTSOCKET sock, int events)
   {
       // `events` contains bits to be set, so:
       //
       // 1. If no notice object exists, add it exactly with `events`.
       // 2. If it exists, only set the bits from `events`.
       // ASSUME: 'events' is not 0, that is, we have some readiness

        // 事件不存在，创建之
       if (wait.notit == nullNotice()) // No notice object
       {
           // Add new event notice and bind to the wait object.
           m_USockEventNotice.push_back(Notice(&wait, sock, events));
           wait.notit = --m_USockEventNotice.end();

           return;
       }

       // We have an existing event notice, so update it

       // 事件已存在，更新之
       wait.notit->events |= events;
   }

   // This function only updates the corresponding event notice object
   // according to the change in the events.

   // 更新事件
   void updateEventNotice(Wait& wait, SRTSOCKET sock, int events, bool enable)
   {
        // 启用事件
       if (enable)
       {
            // 添加触发的事件
           addEventNotice(wait, sock, events);
       }
       // 禁用事件
       else
       {
           removeExcessEvents(wait, ~events);
       }
   }

    // 移除某个socket所有订阅事件和已触发的事件
   void removeSubscription(SRTSOCKET u)
   {
       std::map<SRTSOCKET, Wait>::iterator i = m_USockWatchState.find(u);
       if (i == m_USockWatchState.end())
           return;

       if (i->second.notit != nullNotice())
       {
           m_USockEventNotice.erase(i->second.notit);
           // NOTE: no need to update the Wait::notit field
           // because the Wait object is about to be removed anyway.
       }
       m_USockWatchState.erase(i);
   }

    // 清除所有事件
   void clearAll()
   {
       m_USockEventNotice.clear();
       m_USockWatchState.clear();
   }

    // 移除所有已触发的事件
   void removeExistingNotices(Wait& wait)
   {
       m_USockEventNotice.erase(wait.notit);
       wait.notit = nullNotice();
   }

    // 移除已触发的事件
   void removeEvents(Wait& wait)
   {
       if (wait.notit == nullNotice())
           return;
       removeExistingNotices(wait);
   }

   // This function removes notices referring to
   // events that are NOT present in @a nevts, but
   // may be among subscriptions and therefore potentially
   // have an associated notice.

   // 清除多余的事件，只保留nevts中指定的事件
   void removeExcessEvents(Wait& wait, int nevts)
   {
       // Update the event notice, should it exist
       // If the watch points to a null notice, there's simply
       // no notice there, so nothing to update or prospectively
       // remove - but may be something to add.
       
       // 事件不存在，直接返回
       if (wait.notit == nullNotice())
           return;

       // `events` contains bits to be cleared.
       // 1. If there is no notice event, do nothing - clear already.
       // 2. If there is a notice event, update by clearing the bits
       // 2.1. If this made resulting state to be 0, also remove the notice.

        // 计算新的事件状态，通过与运算仅保留nevts中设置的事件
       const int newstate = wait.notit->events & nevts;
       // 还有需要关注的事件
       if (newstate)
       {
           wait.notit->events = newstate;
       }
       // 没有需要关注的事件了，移除epoll事件
       else
       {
           // If the new state is full 0 (no events),
           // then remove the corresponding notice object
           removeExistingNotices(wait);
       }
   }

    // 检查是否是一个边缘触发事件，如果是则清除之，因为边缘触发只需要通知一次
   bool checkEdge(enotice_t::iterator i)
   {
       // This function should check if this event was subscribed
       // as edge-triggered, and if so, clear the event from the notice.
       // Update events and check edge mode at the subscriber

       // 清除边缘触发事件
       i->events &= ~i->parent->edgeOnly();
       // 边缘触发只需要通知一次，通知完成后，移除对象
       if(!i->events)
       {
           removeExistingNotices(*i->parent);
           return true;
       }
       return false;
   }

   /// This should work in a loop around the notice container of
   /// the given eid container and clear out the notice for
   /// particular event type. If this has cleared effectively the
   /// last existing event, it should return the socket id
   /// so that the caller knows to remove it also from subscribers.
   ///
   /// @param i iterator in the notice container
   /// @param event event type to be cleared
   /// @retval (socket) Socket to be removed from subscriptions
   /// @retval SRT_INVALID_SOCK Nothing to be done (associated socket
   ///         still has other subscriptions)

   // 清除特定事件的通知,清除成功后返回socket以便于进一步清理
   SRTSOCKET clearEventSub(enotice_t::iterator i, int event)
   {
       // We need to remove the notice and subscription
       // for this event. The 'i' iterator is safe to
       // delete, even indirectly.

       // This works merely like checkEdge, just on request to clear the
       // identified event, if found.

       // 检查通知对象是否包含指定的事件
       if (i->events & event)
       {
           // The notice has a readiness flag on this event.
           // This means that there exists also a subscription.

           // 清除事件，返回socket
           Wait* w = i->parent;
           if (w->clear(event))
               return i->fd;
       }

       return SRT_INVALID_SOCK;
   }
};


// SRT Epoll封装
class CEPoll
{
friend class srt::CUDT;
friend class srt::CUDTGroup;
friend class srt::CRendezvousQueue;

public:
   CEPoll();
   ~CEPoll();

public: // for CUDTUnited API

   /// create a new EPoll.
   /// @return new EPoll ID if success, otherwise an error number.

   // 创建一个SRT Epoll实例
   int create(CEPollDesc** ppd = 0);


   /// delete all user sockets (SRT sockets) from an EPoll
   /// @param [in] eid EPoll ID.
   /// @return 0 

   // 清除一个SRT Epoll实例对应的所有socket
   int clear_usocks(int eid);

   /// add a system socket to an EPoll.
   /// @param [in] eid EPoll ID.
   /// @param [in] s system Socket ID.
   /// @param [in] events events to watch.
   /// @return 0 if success, otherwise an error number.

	// 向epoll中添加一个系统套接字SYSSOCKET
   int add_ssock(const int eid, const SYSSOCKET& s, const int* events = NULL);

   /// remove a system socket event from an EPoll; socket will be removed if no events to watch.
   /// @param [in] eid EPoll ID.
   /// @param [in] s system socket ID.
   /// @return 0 if success, otherwise an error number.

	// 删除一个SYSSOCKET
   int remove_ssock(const int eid, const SYSSOCKET& s);
   /// update a UDT socket events from an EPoll.
   /// @param [in] eid EPoll ID.
   /// @param [in] u UDT socket ID.
   /// @param [in] events events to watch.
   /// @return 0 if success, otherwise an error number.

	// 更新SRTSOCKET订阅的事件
   int update_usock(const int eid, const SRTSOCKET& u, const int* events);

   /// update a system socket events from an EPoll.
   /// @param [in] eid EPoll ID.
   /// @param [in] u UDT socket ID.
   /// @param [in] events events to watch.
   /// @return 0 if success, otherwise an error number.

	// 更新SYSSOCKET订阅的事件
   int update_ssock(const int eid, const SYSSOCKET& s, const int* events = NULL);

   /// wait for EPoll events or timeout.
   /// @param [in] eid EPoll ID.
   /// @param [out] readfds UDT sockets available for reading.
   /// @param [out] writefds UDT sockets available for writing.
   /// @param [in] msTimeOut timeout threshold, in milliseconds.
   /// @param [out] lrfds system file descriptors for reading.
   /// @param [out] lwfds system file descriptors for writing.
   /// @return number of sockets available for IO.

	// 等待事件或超时
   int wait(const int eid, std::set<SRTSOCKET>* readfds, std::set<SRTSOCKET>* writefds, int64_t msTimeOut, std::set<SYSSOCKET>* lrfds, std::set<SYSSOCKET>* lwfds);

   typedef std::map<SRTSOCKET, int> fmap_t;

   /// Lightweit and more internal-reaching version of `uwait` for internal use only.
   /// This function wait for sockets to be ready and reports them in `st` map.
   ///
   /// @param d the internal structure of the epoll container
   /// @param st output container for the results: { socket_type, event }
   /// @param msTimeOut timeout after which return with empty output is allowed
   /// @param report_by_exception if true, errors will result in exception intead of returning -1
   /// @retval -1 error occurred
   /// @retval >=0 number of ready sockets (actually size of `st`)

   // 内部使用的SRTSOCKET wait   
   int swait(CEPollDesc& d, fmap_t& st, int64_t msTimeOut, bool report_by_exception = true);

   /// Empty subscription check - for internal use only.
   bool empty(const CEPollDesc& d) const;

   /// Reports which events are ready on the given socket.
   /// @param mp socket event map retirned by `swait`
   /// @param sock which socket to ask
   /// @return event flags for given socket, or 0 if none
   static int ready(const fmap_t& mp, SRTSOCKET sock)
   {
       fmap_t::const_iterator y = mp.find(sock);
       if (y == mp.end())
           return 0;
       return y->second;
   }

   /// Reports whether socket is ready for given event.
   /// @param mp socket event map retirned by `swait`
   /// @param sock which socket to ask
   /// @param event which events it should be ready for
   /// @return true if the given socket is ready for given event
   static bool isready(const fmap_t& mp, SRTSOCKET sock, SRT_EPOLL_OPT event)
   {
       return (ready(mp, sock) & event) != 0;
   }

   // Could be a template directly, but it's now hidden in the imp file.
   void clear_ready_usocks(CEPollDesc& d, int direction);

   /// wait for EPoll events or timeout optimized with explicit EPOLL_ERR event and the edge mode option.
   /// @param [in] eid EPoll ID.
   /// @param [out] fdsSet array of user socket events (SRT_EPOLL_IN | SRT_EPOLL_OUT | SRT_EPOLL_ERR).
   /// @param [int] fdsSize of fds array
   /// @param [in] msTimeOut timeout threshold, in milliseconds.
   /// @return total of available events in the epoll system (can be greater than fdsSize)

   int uwait(const int eid, SRT_EPOLL_EVENT* fdsSet, int fdsSize, int64_t msTimeOut);

   /// close and release an EPoll.
   /// @param [in] eid EPoll ID.
   /// @return 0 if success, otherwise an error number.

   int release(const int eid);

public: // for CUDT to acknowledge IO status

   /// Update events available for a UDT socket. At the end this function
   /// counts the number of updated EIDs with given events.
   /// @param [in] uid UDT socket ID.
   /// @param [in] eids EPoll IDs to be set
   /// @param [in] events Combination of events to update
   /// @param [in] enable true -> enable, otherwise disable
   /// @return -1 if invalid events, otherwise the number of changes

   int update_events(const SRTSOCKET& uid, std::set<int>& eids, int events, bool enable);

   int setflags(const int eid, int32_t flags);

private:
	// 用于生成唯一标识
   int m_iIDSeed;                            // seed to generate a new ID
   srt::sync::Mutex m_SeedLock;

	// 使用map来维护所有的epoll实例
   std::map<int, CEPollDesc> m_mPolls;       // all epolls
   mutable srt::sync::Mutex m_EPollLock;
};

#if ENABLE_HEAVY_LOGGING
std::string DisplayEpollResults(const std::map<SRTSOCKET, int>& sockset);
#endif

} // namespace srt


#endif
