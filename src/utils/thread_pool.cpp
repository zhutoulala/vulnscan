#include <assert.h>
#include <functional>
#include <utility>
#include "thread_pool.h"

CThreadPool::CThreadPool() : 
    CThreadPool (std::max(std::thread::hardware_concurrency(), 2u) - 1u){

}

CThreadPool::CThreadPool(uint32_t iNumThreads) :
    m_done(false),
    m_workQueue{},
    m_threads{} {
    try
    {
        for (std::uint32_t i = 0u; i < iNumThreads; ++i)
        {
            m_threads.emplace_back(&CThreadPool::worker, this);
        }
    }
    catch (...)
    {
        destroy();
        throw;
    }
}

CThreadPool::~CThreadPool() {
    destroy();
}

void CThreadPool::worker() {
    while (!m_done) {
        std::unique_ptr<IThreadTask> spThreadTask;
        if (m_workQueue.waitPop(spThreadTask)) {
            assert(spThreadTask != nullptr);
            spThreadTask->execute();
        }
    }
}

void CThreadPool::destroy() {
    m_done = true;
    for (auto& thread : m_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}