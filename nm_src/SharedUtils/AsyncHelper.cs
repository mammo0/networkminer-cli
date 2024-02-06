using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharedUtils {
    public static class AsyncHelper {

        public static async Task<Task> RunCancelOrTimeout(Task task, CancellationToken cancellationToken, int timeoutMilliseconds) {
            TaskCompletionSource<bool> cancelWaiter = new TaskCompletionSource<bool>();
            using (cancellationToken.Register(() => cancelWaiter.TrySetCanceled())) {
                using (CancellationTokenSource timeoutSource = new CancellationTokenSource(timeoutMilliseconds)) {
                    TaskCompletionSource<bool> timeoutTask = new TaskCompletionSource<bool>();
                    using (timeoutSource.Token.Register(() => timeoutTask.TrySetResult(true))) {
                        return await Task.WhenAny(task, timeoutTask.Task, cancelWaiter.Task);
                    }
                }
            }
        }

        public static async Task<Task> RunOrTimeout(Task task, int timeoutMilliseconds) {
            using (CancellationTokenSource timeoutSource = new CancellationTokenSource(timeoutMilliseconds)) {
                TaskCompletionSource<bool> timeoutTask = new TaskCompletionSource<bool>();
                using (timeoutSource.Token.Register(() => timeoutTask.TrySetResult(true))) {
                    return await Task.WhenAny(task, timeoutTask.Task);
                }
            }
        }

        public static async Task<bool> TryRunTask(Func<CancellationToken, Task> taskFunction, CancellationToken cancellationToken, int timeoutMilliseconds) {
            using (CancellationTokenSource timeout = new CancellationTokenSource(timeoutMilliseconds)) {
                using (cancellationToken.Register(timeout.Cancel)) {
                    try {
                        await taskFunction(timeout.Token);
                        if (timeout.IsCancellationRequested)
                            return false;
                    }
                    catch (OperationCanceledException) {
                        return false;
                    }
                    return true;
                }
            }
        }

        public static async Task<(bool IsSuccess, T Result)> TryRunTask<T>(Func<CancellationToken, Task<T>> taskFunction, CancellationToken cancellationToken, int timeoutMilliseconds) {
            using (CancellationTokenSource timeout = new CancellationTokenSource(timeoutMilliseconds)) {
                using (cancellationToken.Register(timeout.Cancel)) {
                    T result = default;
                    try {
                        result = await taskFunction(timeout.Token);
                        if (timeout.IsCancellationRequested)
                            return (false, result);
                    }
                    catch (OperationCanceledException) {
                        return (false, result);
                    }
                    return (true, result);
                }
            }
        }

        public static async Task<bool> TryRunTaskNoCancelOnTimeout(Task task, int timeoutMilliseconds) {
            //This function doesn't cancel the task when there is a timeout.
            //It also doens't use any try catch, which can be good for performance if timeouts occurr frequently
            using (Task completedTask = await RunOrTimeout(task, timeoutMilliseconds)) {
                return completedTask == task && !task.IsCanceled && !task.IsFaulted;
            }
        }
        public static async Task<bool> TryRunTaskNoCancelOnTimeout(Task task, int timeoutMilliseconds, CancellationToken cancellationToken) {
            //This function doesn't cancel the task when there is a timeout.
            //It also doens't use any try catch, which can be good for performance if timeouts occurr frequently
            using (Task completedTask = await RunCancelOrTimeout(task, cancellationToken, timeoutMilliseconds)) {
                return completedTask == task && !task.IsCanceled && !task.IsFaulted;
            }

            /*
            TaskCompletionSource<bool> cancelWaiterProducer = new TaskCompletionSource<bool>();
            using (cancellationToken.Register(() => cancelWaiterProducer.TrySetCanceled())) {
                using (CancellationTokenSource timeout = new CancellationTokenSource(timeoutMilliseconds)) {
                    TaskCompletionSource<bool> timeoutProducer = new TaskCompletionSource<bool>();
                    using (timeout.Token.Register(() => timeoutProducer.TrySetResult(true))) {
                        using (Task completedTask = await Task.WhenAny(task, timeoutProducer.Task, cancelWaiterProducer.Task)) {
                            return completedTask == task && !task.IsCanceled && !task.IsFaulted;
                        }
                    }
                }
            }
            */
        }
    }
}
