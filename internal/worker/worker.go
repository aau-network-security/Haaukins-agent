package worker

import "github.com/rs/zerolog/log"

// WorkerPool is a contract for Worker Pool implementation
type WorkerPool interface {
	Run()
	AddTask(task func())
}

type workerPool struct {
	maxWorkers  int
	queuedTasks chan func()
}

func NewWorkerPool(maxWorkers int) WorkerPool {
	queuedTasks := make(chan func())
	return &workerPool{
		maxWorkers:  maxWorkers,
		queuedTasks: queuedTasks,
	}
}
func (wp *workerPool) Run() {
	for i := 0; i < wp.maxWorkers; i++ {
		log.Debug().Int("workerId", i+1).Msg("starting worker")
		go func(workerID int) {
			for task := range wp.queuedTasks {
				task()
			}
		}(i + 1)
	}
}

func (wp *workerPool) AddTask(task func()) {
	wp.queuedTasks <- task
}
