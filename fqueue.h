#pragma once

#include <thread>
#include <mutex>
#include <queue>
#include <type_traits>

#include <cassert>

// uses external GetSize(packet)

template<typename PACKET, size_t MAX_QUEUE_SIZE, size_t MAX_FRAMES>
class FQueue
{
public:
    FQueue() : m_packetsSize(0) {}
    FQueue(const FQueue&) = delete;
    FQueue& operator=(const FQueue&) = delete;

    template<typename T = std::false_type>
    bool push(const PACKET& packet, T abortFunc = T())
    {
        bool wasEmpty;
        {
            std::unique_lock<std::mutex> locker(m_mutex);
            while (isPacketsQueueFull())
            {
                if (abortFunc())
                {
                    return false;
                }
                m_condVar.wait(locker);
            }
            wasEmpty = m_queue.empty();
            enqueue(packet);
        }
        if (wasEmpty)
        {
            m_condVar.notify_all();
        }

        return true;
    }

    template<typename T = std::false_type>
    bool pop(PACKET& packet, T abortFunc = T())
    {
        bool wasFull;
        {
            std::unique_lock<std::mutex> locker(m_mutex);

            while (m_queue.empty())
            {
                if (abortFunc())
                {
                    return false;
                }
                m_condVar.wait(locker);
            }

            wasFull = isPacketsQueueFull();
            packet = dequeue();
        }
        if (wasFull)
        {
            m_condVar.notify_all();
        }

        return true;
    }

    void clear()
    {
        for (auto& packet : m_queue)
        {
            av_packet_unref(&packet);
        }
        m_packetsSize = 0;
        std::deque<PACKET>().swap(m_queue);
    }

    bool empty()
    {
        boost::lock_guard<boost::mutex> locker(m_mutex);
        return m_queue.empty();
    }

    void notify()
    {
        m_condVar.notify_all();
    }

private:
    auto dequeue()
    {
        assert(!m_queue.empty());
        auto packet = m_queue.front();
        m_queue.pop();
        m_packetsSize -= GetSize(packet);
        assert(m_packetsSize >= 0);
        return packet;
    }

    void enqueue(const PACKET& packet)
    {
        m_packetsSize += GetSize(packet);
        assert(m_packetsSize >= 0);
        m_queue.push(packet);
    }

    bool isPacketsQueueFull() const
    {
        return m_packetsSize > MAX_QUEUE_SIZE ||
            m_queue.size() > MAX_FRAMES;
    }

private:
    int64_t	m_packetsSize;
    std::queue<PACKET> m_queue;

    std::mutex m_mutex;
    std::condition_variable m_condVar;
};
