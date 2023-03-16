package worker

import "github.com/rs/zerolog/log"

// WorkerPool is a contract for Worker Pool implementation
type WorkerPool interface {
	Run()
	AddTask(task func())
	GetAmountOfQueuedTasks() uint32
}

type workerPool struct {
	maxWorkers  int
	queuedTasks chan func()
}

func NewWorkerPool(maxWorkers int) WorkerPool {
	queuedTasks := make(chan func(), 200)
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
				log.Debug().Int("workderId", workerID).Msg("worker is running task")
				task()
				log.Debug().Int("workderId", workerID).Msg("worker is done running task")
			}
		}(i + 1)
	}
}

func (wp *workerPool) GetAmountOfQueuedTasks() uint32 {
	return uint32(len(wp.queuedTasks))
}

func (wp *workerPool) AddTask(task func()) {
	wp.queuedTasks <- task
}
