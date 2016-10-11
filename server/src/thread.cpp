#include "thread.h"

#include <string>

#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#include "log.h"

mutex::mutex() { pthread_mutex_init(&m,NULL); }
mutex::~mutex() { pthread_mutex_destroy(&m); }
void mutex::lock() { pthread_mutex_lock(&m); }
void mutex::unlock() { pthread_mutex_unlock(&m); }

thread::thread(): _stopped(true) {}

void * thread::_start(void * _t)
{
	thread* _this = (thread*)_t;
	_this->_pid = (unsigned long) _this->_td;
	_this->thread_pid = syscall(SYS_gettid);
	dbg("starting %lu",(unsigned long)_this->thread_pid);
	_this->run();
	dbg("ended %lu",(unsigned long)_this->thread_pid);
	_this->_stopped.set(true);
	return NULL;
}

void thread::start()
{
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr,1024*1024);// 1 MB

	int res;
	_pid = 0;

	this->_stopped.lock();
	if(!(this->_stopped.unsafe_get())){
		this->_stopped.unlock();
		err("thread already running");
		return;
	}
	this->_stopped.unsafe_set(false);
	this->_stopped.unlock();

	res = pthread_create(&_td,&attr,_start,this);
	pthread_attr_destroy(&attr);
	if (res != 0) {
		err("pthread create failed with code %i", res);
		throw std::string("thread could not be started");
	}
}

void thread::stop()
{
	_m_td.lock();

	if(is_stopped()){
		dbg("already stopped");
		_m_td.unlock();
		return;
	}

	// gives the thread a chance to clean up
	dbg("stop thread %lu", (unsigned long int)thread_pid);

	try { on_stop(); } catch(...) {}

	int res;
	if ((res = pthread_detach(_td)) != 0) {
		if (res == EINVAL) {
			err("pthread_detach failed with code EINVAL: thread already in detached state");
		} else if (res == ESRCH) {
			err("pthread_detach failed with code ESRCH: thread could not be found");
		} else {
			err("pthread_detach failed with code %i", res);
		}
	}

	dbg("thread %lu detached", (unsigned long int)thread_pid);

	_m_td.unlock();
}

void thread::join()
{
	if(!is_stopped())
		pthread_join(_td,NULL);
}

void thread::set_name(const char *thread_name)
{
	_m_td.lock();
	if(thread_name != NULL &&
		(pthread_setname_np(_td, thread_name)!=0))
		err("can't set name '%s' for thread %i[%p] ",thread_name,thread_pid,this);
	_m_td.unlock();
}
