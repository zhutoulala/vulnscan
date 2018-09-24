#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>

/**
 * A thread safe task queue
 */
template<typename T>
class CTaskQueue {
 
public:
    /**
     * attempt to get the first value in the queue.
     * @return true if succeed, false otherwise.
     */
    bool tryPop(T& out) {
        std::lock_guard<std::mutex> lock{ m_mutex };
        if (m_queue.empty() || !m_valid) {
            return false;
        }
        out = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    /**
     * wait to get the first value in the queue.
     * will block until a value is available unless clear is called or the instance is destructed.
     * @return true if succeed, false otherwise.
     */
    bool waitPop(T& out) {
        std::unique_lock<std::mutex> lock{ m_mutex };
        m_condition.wait(lock, [this]() {
            return !m_queue.empty() || !m_valid;
        });

        if (!m_valid) {
            return false;
        }

        out = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    /**
    * Push a new value onto the queue.
    */
    void push(T value) {
        std::lock_guard<std::mutex> lock{ m_mutex };
        m_queue.push(std::move(value));
        m_condition.notify_one();
    }


    /**
    * Check whether or not the queue is empty.
    */
    bool empty(void) const {
        std::lock_guard<std::mutex> lock{ m_mutex };
        return m_queue.empty();
    }

    /**
    * Clear all items from the queue.
    */
    void clear(void) {
        std::lock_guard<std::mutex> lock{ m_mutex };
        while (!m_queue.empty())
        {
            m_queue.pop();
        }
        m_condition.notify_all();
    }

    /**
    * Invalidate the queue.
    * Used to ensure no conditions are being waited on in waitPop when
    * a thread or the application is trying to exit.
    * The queue is invalid after calling this method and it is an error
    * to continue using a queue after this method has been called.
    */
    void invalidate(void) {
        std::lock_guard<std::mutex> lock{ m_mutex };
        m_valid = false;
        m_condition.notify_all();
    }

    /**
    * Returns whether or not this queue is valid.
    */
    bool isValid(void) const {
        std::lock_guard<std::mutex> lock{ m_mutex };
        return m_valid;
    }

private:
    std::atomic_bool m_valid{true};
    mutable std::mutex m_mutex;
    std::queue<T> m_queue;
    std::condition_variable m_condition;
};