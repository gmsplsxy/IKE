#include "queue.h"

#include <stdlib.h>

typedef struct _node_t _node_t;
struct _node_t {
	void*			ptr;
	_node_t*	prev;
	_node_t*	next;
};

_node_t*	_node_create(void* data);

queue_t* que_create()
{
	queue_t* que = calloc(1, sizeof(queue_t));

	pthread_mutex_init(&que->mutex, NULL);
	pthread_cond_init(&que->cond, NULL);

	return que;
}

_node_t* _node_create(void* data)
{
	_node_t* node = calloc(1, sizeof(_node_t));
	node->ptr = data;

	return node;
}

void enqueue(queue_t* que, void* data)
{
	_node_t* node = _node_create(data);

	pthread_mutex_lock(&que->mutex);
	if(que->rear == NULL) {
		que->rear = que->front = node;
	}
	else {
		((_node_t*)que->front)->prev = node;
		node->next = que->front;
		que->front = node;
	}
	pthread_cond_signal(&que->cond);
	pthread_mutex_unlock(&que->mutex);
}

void* dequeue(queue_t* que)
{
	void* data = NULL;

	pthread_mutex_lock(&que->mutex);
	pthread_cond_wait(&que->cond, &que->mutex);
	if(que->rear != NULL) {
		_node_t* node = que->rear;
		// if only 1 node
		if(que->rear == que->front) {
			que->rear = que->front = NULL;
		} else {
			(node->prev)->next = NULL;
			que->rear = node->prev;
		}

		data = node->ptr;
		node->ptr = NULL;
		free(node);
	}
	pthread_mutex_unlock(&que->mutex);

	return data;
}
