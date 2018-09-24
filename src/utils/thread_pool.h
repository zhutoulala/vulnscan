#pragma once

#include <atomic>
#include <thread>
#include "task_queue.h"
#include "thread_task.h"

class CThreadPool {
public:
    CThreadPool();
    CThreadPool(uint32_t iNumThreads);

    /**
    * Non-copyable.
    */
    CThreadPool(const CThreadPool& rhs) = delete;

    /**
    * Non-assignable.
    */
    CThreadPool& operator=(const CThreadPool& rhs) = delete;
    ~CThreadPool();

    template <typename Func, typename... Args>
    auto submit(Func&& func, Args&&... args)
    {
        auto boundTask = std::bind(std::forward<Func>(func), std::forward<Args>(args)...);
        using ResultType = std::result_of_t<decltype(boundTask)()>;
        using PackagedTask = std::packaged_task<ResultType()>;
        using CTaskType = CThreadTask<PackagedTask>;

        PackagedTask task{ std::move(boundTask) };
        CTaskFuture<ResultType> result{ task.get_future() };
        m_workQueue.push(std::make_unique<CTaskType>(std::move(task)));
        return result;
    }


private:
    /**
     * Constantly running function each thread uses to acquire work items from the queue.
     */
    void worker();
     
    /**
     * Invalidates the queue and joins all running threads.
     */
    void destroy();

private:
    std::atomic_bool m_done;
    CTaskQueue<std::unique_ptr<IThreadTask>> m_workQueue;
    std::vector<std::thread> m_threads;
 };

class CThreadPoolFactory {
public:
    static std::unique_ptr<CThreadPool> getThreadPool() {
        return std::make_unique<CThreadPool>();
    }
};