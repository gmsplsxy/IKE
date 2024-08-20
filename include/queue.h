#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <pthread.h>

typedef struct {
  void*   front;
  void*   rear;

  pthread_mutex_t  mutex;
  pthread_cond_t   cond;
}queue_t;

queue_t*  que_create();
// Free at Caller
//void      que_free(queue_t** que);
void      enqueue(queue_t* que, void* data);
void*     dequeue(queue_t* que);

#endif //__QUEUE_H__
