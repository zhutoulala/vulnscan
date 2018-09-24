#pragma once

#include <future>
#include <memory>
#include <thread>

class IThreadTask
{
public:
    IThreadTask(void) = default;
    virtual ~IThreadTask(void) = default;
    IThreadTask(const IThreadTask& rhs) = delete;
    IThreadTask& operator=(const IThreadTask& rhs) = delete;
    IThreadTask(IThreadTask&& other) = default;
    IThreadTask& operator=(IThreadTask&& other) = default;

    /**
     * Run the task.
     */
    virtual void execute() = 0;
};

template <typename Func>
class CThreadTask : public IThreadTask
{
public:
    CThreadTask(Func&& func)
        :m_func{ std::move(func) }
    {
    }

    ~CThreadTask(void) override = default;
    CThreadTask(const CThreadTask& rhs) = delete;
    CThreadTask& operator=(const CThreadTask& rhs) = delete;
    CThreadTask(CThreadTask&& other) = default;
    CThreadTask& operator=(CThreadTask&& other) = default;

    /**
     * Run the task.
     */
    void execute() override
    {
        m_func();
    }

private:
    Func m_func;
};

    
/**
 * A wrapper around a std::future that adds the behavior of futures returned from std::async.
 * Specifically, this object will block and wait for execution to finish before going out of scope.
 */
template <typename T>
class CTaskFuture
{
public:
    CTaskFuture(std::future<T>&& future)
        :m_future{ std::move(future) }
    {
    }

    CTaskFuture(const CTaskFuture& rhs) = delete;
    CTaskFuture& operator=(const CTaskFuture& rhs) = delete;
    CTaskFuture(CTaskFuture&& other) = default;
    CTaskFuture& operator=(CTaskFuture&& other) = default;
    ~CTaskFuture(void)
    {
        if (m_future.valid())
        {
            m_future.get();
        }
    }

    auto get(void)
    {
        return m_future.get();
    }


private:
    std::future<T> m_future;
};