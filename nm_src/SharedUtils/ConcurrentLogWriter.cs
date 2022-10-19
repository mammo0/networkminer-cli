using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharedUtils
{
    public class ConcurrentLogWriter : System.IO.TextWriter, IDisposable {

        private System.IO.FileStream fs;
        private readonly SemaphoreSlim writeLock;
        private readonly char columnSeparator;

        public override Encoding Encoding {
            get {
                return Encoding.UTF8;
            }
        }

        /// <summary>
        /// The output stream will be flushed if time since last write operation
        /// is greater than AutoFlushInterval. A value of zero, or a negative value,
        /// disables the auto flush.
        /// </summary>
        public TimeSpan AutoFlushInterval { get; set; } = TimeSpan.Zero;
        private DateTime lastFlush = DateTime.Now;

        public override string NewLine { get; set; } = "\r\n";

        [Obsolete]
        private ConcurrentLogWriter() { }

        public ConcurrentLogWriter(string path, char columnSeparator = '\t') {
            this.columnSeparator = columnSeparator;
            this.AppendOrCreate(path);
            this.writeLock = new SemaphoreSlim(1, 1);
        }

        private bool IsTimeToFlush() {
            return this.AutoFlushInterval > TimeSpan.Zero && this.lastFlush.Add(this.AutoFlushInterval) < DateTime.Now;
        }

        private void AppendOrCreate(string path) {
            this.fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            //this.fs.Seek(0, System.IO.SeekOrigin.End);
        }

        private void ReOpen() {
            try {
                this.fs.Close();
            }
            catch { }
            this.AppendOrCreate(this.fs.Name);
        }


        public override void Flush() {
            this.writeLock.Wait();
            try {
                this.fs.Flush();
            }
            catch {
                this.ReOpen();
            }
            finally {
                this.writeLock.Release();
            }
        }

        public override async Task FlushAsync() {
            await this.writeLock.WaitAsync();
            try {
                await this.fs.FlushAsync();
            }
            catch {
                this.ReOpen();
            }
            finally {
                this.writeLock.Release();
            }
        }

        public override async Task WriteLineAsync(string line) {
            byte[] bytes = this.Encoding.GetBytes(line + this.NewLine);
            await this.writeLock.WaitAsync();
            try {
                await this.fs.WriteAsync(bytes, 0, bytes.Length);
            }
            catch {
                this.ReOpen();
                await this.fs.WriteAsync(bytes, 0, bytes.Length);
            }
            finally {
                this.writeLock.Release();
            }

            if (this.IsTimeToFlush()) {
                this.lastFlush = DateTime.Now;
                await this.FlushAsync();
            }
        }

        public override void WriteLine(string line) {
            byte[] bytes = this.Encoding.GetBytes(line + this.NewLine);
            this.writeLock.Wait();
            try {
                this.fs.Write(bytes, 0, bytes.Length);
            }
            catch {
                this.ReOpen();
                this.fs.Write(bytes, 0, bytes.Length);
            }
            finally {
                this.writeLock.Release();
            }

            if(this.IsTimeToFlush()) {
                this.lastFlush = DateTime.Now;
                this.Flush();
            }
        }

        public async Task LogAsync(params string[] columns) {
            await this.LogAsync(columns as IEnumerable<string>, true);
        }

        public async Task LogAsync(IEnumerable<string> columns, bool prependTimestamp = true) {
            //StringBuilder logLine = new StringBuilder(DateTime.UtcNow.ToString("s", System.Globalization.CultureInfo.InvariantCulture));
            StringBuilder logLine = new StringBuilder();
            if(prependTimestamp)
                logLine.Append(DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
            foreach (string c in columns) {
                logLine.Append(this.columnSeparator);
                if(c != null)
                    logLine.Append(c);
            }
            await this.WriteLineAsync(logLine.ToString());
        }


        public override void Close() {
            fs.Close();
            base.Close();
        }

        public new void Dispose() {
            fs.Dispose();
            base.Dispose();
        }


    }
}
