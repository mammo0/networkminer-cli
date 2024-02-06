using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedUtils {

    
    public class NamedPipeReader : IDisposable {

        private readonly System.Diagnostics.Process process;
        private readonly string outputFilePath;
        private System.IO.FileInfo outputFileInfo;
        private State state;
        private bool disposedValue;

        enum State {
            ProcessNotStarted,
            WaitingForFile,
            WritingToFile,
            ProcessStoped,
            Stopped
        }

        public long BytesReadTotal { get; private set; }
        public bool HasStopped { get { return this.state == State.Stopped; } }

        public ushort UpdateTimeMilliseconds { get; private set; }


        public NamedPipeReader(string pipeName, string outputFilePath, bool requireAdmin, string bpf = null, ushort updateTimeMilliseconds = 500, Tuple<string, string, System.Security.SecureString> runAs = null) {
            this.UpdateTimeMilliseconds = updateTimeMilliseconds;
            this.BytesReadTotal = 0;
            if (System.IO.Directory.GetFiles(@"\\.\pipe\", pipeName).Length < 1)
                throw new Exception("Named pipe " + pipeName + " doesn't exist");
            this.state = State.ProcessNotStarted;
            this.outputFilePath = outputFilePath;
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.FileName = "powershell.exe";

            string direction = "In";
            if (!string.IsNullOrEmpty(bpf))
                direction = "InOut";
            StringBuilder ps = new StringBuilder();
            ps.AppendLine("-NonInteractive -NoProfile -Command $pipeStream = new-object System.IO.Pipes.NamedPipeClientStream '.','" + pipeName + "','" + direction + "';");
            ps.AppendLine("$file = New-Object IO.FileStream '" + this.outputFilePath + "' ,'OpenOrCreate','Write','ReadWrite';");

            ps.AppendLine("try {");
            ps.AppendLine("    $pipeStream.Connect(3000);");
            if (!string.IsNullOrEmpty(bpf)) {
                ps.AppendLine("    $bpf = [Text.Encoding]::ASCII.GetBytes('" + bpf + "');");
                ps.AppendLine("    $pipeStream.Write($bpf, 0, $bpf.Length);");
            }
            ps.AppendLine("    $nextUpdate = (Get-Date).AddMilliseconds(" + this.UpdateTimeMilliseconds + ")");
            ps.AppendLine("    $buffer = new-object byte[] 4096;");
            ps.AppendLine("    $n = $pipeStream.Read($buffer, 0, $buffer.Length);");
            ps.AppendLine("    while ($n -gt 0) {");
            ps.AppendLine("        $file.Write($buffer, 0, $n);");
            ps.AppendLine("        if ($nextUpdate -gt (Get-Date)) {");
            ps.AppendLine("            $file.Flush();");
            ps.AppendLine("            $nextUpdate = (Get-Date).AddMilliseconds(" + this.UpdateTimeMilliseconds + ")");
            ps.AppendLine("        }");
            ps.AppendLine("        $n = $pipeStream.Read($buffer, 0, $buffer.Length);");
            ps.AppendLine("    }");
            ps.AppendLine("}");
            ps.AppendLine("finally {");
            ps.AppendLine("    $file.Close();");
            ps.AppendLine("    $pipeStream.Dispose();");
            ps.AppendLine("}");
            startInfo.Arguments = ps.ToString();

            //startInfo.RedirectStandardOutput = true;
            //startInfo.RedirectStandardError = true;
            //startInfo.CreateNoWindow = false;
            startInfo.CreateNoWindow = true;
            if (requireAdmin)
                startInfo.Verb = "runas";
            if(runAs == null || string.IsNullOrEmpty(runAs.Item1))
                startInfo.UseShellExecute = true;
            else {
                startInfo.UseShellExecute = false;
                startInfo.UserName = runAs.Item1;
                if(!string.IsNullOrEmpty(runAs.Item2))
                    startInfo.Domain = runAs.Item2;
                startInfo.Password = runAs.Item3;
            }
            
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.ErrorDialog = true;

            this.process = new System.Diagnostics.Process {
                StartInfo = startInfo
            };
            if (this.process.Start())
                this.state = State.WaitingForFile;
            else {
                this.state = State.Stopped;
                if (this.process?.Responding == true && !this.process.HasExited)
                    this.state = State.WaitingForFile;
                else {
                    this.Stop(this.process?.HasExited == false);
                    throw new Exception("Could not start process");
                }
            }
            if(this.state == State.WaitingForFile)
                this.process.Exited += (object sender, EventArgs e) => this.Stop(false);
        }
        
        private long GetNewBytesRead() {
            if (outputFileInfo?.Length > 0) {
                long newBytesRead = outputFileInfo.Length - this.BytesReadTotal;
                this.BytesReadTotal += newBytesRead;
                return newBytesRead;
            }
            else
                return 0;
        }

        public async Task<long> ReadAllAsync(System.Threading.CancellationToken cancellationToken, int idleTimeoutMilliseconds = 60000) {
            cancellationToken.Register(() => this.Stop(true));
            long bytesRead = await this.ReadAsync(idleTimeoutMilliseconds);
            while(bytesRead > 0 || this.state != State.Stopped)
                bytesRead = await this.ReadAsync(idleTimeoutMilliseconds);
            return this.BytesReadTotal;
        }

        public async Task<long> ReadAsync(int idleTimeoutMilliseconds = 60000) {

            DateTime idleTimeoutTimestamp = DateTime.Now.AddMilliseconds(idleTimeoutMilliseconds);
            await Task.Delay(this.UpdateTimeMilliseconds);
            if (this.state == State.WaitingForFile) {

                while (!System.IO.File.Exists(this.outputFilePath) && !this.process.HasExited) {
                    if (DateTime.Now > idleTimeoutTimestamp) {//timeout waiting for output file to appear on disk
                        this.Stop(true);
                        throw new TimeoutException("Timed out witing for file from Named Pipe.");
                    }
                    await Task.Delay(this.UpdateTimeMilliseconds);//wait for powershell to start writing to disk
                }
                if (System.IO.File.Exists(outputFilePath)) {
                    this.outputFileInfo = new System.IO.FileInfo(outputFilePath);
                    this.state = State.WritingToFile;
                }
                else {
                    this.Stop();
                    throw new Exception("Process has exited, but no file was written to disk.");
                }
            }
            while (this.state == State.WritingToFile) {
                this.outputFileInfo.Refresh();
                if (process.HasExited) {
                    //this is where we should end up after the writing process has finished
                    this.Stop();
                }
                else if (outputFileInfo.Length > this.BytesReadTotal) {
                    return this.GetNewBytesRead();
                }
                else if (DateTime.Now > idleTimeoutTimestamp) {
                    this.Stop(true);
                    throw new TimeoutException("Timed out reading from local Named Pipe.");
                }
                else
                    await Task.Delay(this.UpdateTimeMilliseconds);
            }
            
            if (this.state == State.Stopped) {
                //double check if additional bytes have been written to disk after process stopped
                if (process.ExitCode != 0) {
                    throw new Exception("Read from Named Pipe process returned " + process.ExitCode);
                }
                else
                    return this.GetNewBytesRead();
            }
            throw new Exception("Unexpected state in named pipe reader: " + this.state);
        }

        public void Stop(bool killProcess = false) {
            this.state = State.Stopped;
            if (killProcess) {
                lock (this.process) {
                    try {
                        if (this.process?.HasExited == false) {
                            this.process.Kill();
                        }
                    }
                    catch { }
                }
            }
        }

        

        protected virtual void Dispose(bool disposing) {
            if (!disposedValue) {
                if (disposing) {
                    // TODO: dispose managed state (managed objects)
                    if (this.state != State.ProcessNotStarted && this.process != null && !this.process.HasExited) {
                        try {
                            this.process.Kill();
                            this.process.Close();
                        }
                        catch { }
                        
                    }
                    this.process.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~NamedPipeReader()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose() {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
