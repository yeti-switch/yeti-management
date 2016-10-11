#pragma once

#include <pthread.h>
#include <sys/time.h>

#include "log.h"

class mutex {
	pthread_mutex_t m;
  public:
	mutex();
	~mutex();
	void lock();
	void unlock();
};

template<class T>
class shared_var
{
	T t;
	mutex m;
public:
	shared_var(const T& _t) : t(_t) {}
	shared_var() {}

	T get() {
		lock();
		T res = unsafe_get();
		unlock();
		return res;
	}

	void set(const T& new_val) {
		lock();
		unsafe_set(new_val);
		unlock();
	}

	void lock() { m.lock(); }
	void unlock() { m.unlock(); }

	const T& unsafe_get() { return t; }
	void unsafe_set(const T& new_val) { t = new_val; }
};

template<class T>
class condition {
	T t;
	pthread_mutex_t m;
	pthread_cond_t  cond;

  public:
	condition(): t() {
		pthread_mutex_init(&m,NULL);
		pthread_cond_init(&cond,NULL);
	}

	~condition() {
		pthread_cond_destroy(&cond);
		pthread_mutex_destroy(&m);
	}

	void set(const T& v) {
		pthread_mutex_lock(&m);
		t = v;
		if(t) pthread_cond_broadcast(&cond);
		pthread_mutex_unlock(&m);
	}

	T get() {
		T v;
		pthread_mutex_lock(&m);
		v = t;
		pthread_mutex_unlock(&m);
		return v;
	}

	void wait_for() {
		pthread_mutex_lock(&m);
		while(!t)
			pthread_cond_wait(&cond,&m);
		pthread_mutex_unlock(&m);
	}

	bool wait_for_to(unsigned long msec) {
		struct timeval now;
		struct timespec timeout;
		int retcode = 0;
		bool ret = false;

		gettimeofday(&now, NULL);
		timeout.tv_sec = now.tv_sec + (msec / 1000);
		timeout.tv_nsec = (now.tv_usec + (msec % 1000)*1000)*1000;
		if(	timeout.tv_nsec >= 1000000000){
			timeout.tv_sec++;
			timeout.tv_nsec -= 1000000000;
		}

		pthread_mutex_lock(&m);
		while(!t && !retcode)
			retcode = pthread_cond_timedwait(&cond,&m, &timeout);

		if(t) ret = true;
		pthread_mutex_unlock(&m);

		return ret;
	}
};

class thread {
	pthread_t _td;
	mutex _m_td;
	shared_var<bool> _stopped;

	static void* _start(void*);

  protected:
	virtual void run()=0;
	virtual void on_stop()=0;
  public:
	unsigned long _pid;
	pid_t thread_pid;

	thread();
	virtual ~thread() {}

	virtual void onIdle() {}

	void start();
	void stop();

	bool is_stopped() { return _stopped.get(); }
	void join();
	void cancel();

	void set_name(const char *thread_name);
};
