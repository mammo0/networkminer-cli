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

        public override string NewLine { get; set; } = "\r\n";

        /*
        public override bool CanRead {
            get {
                return false;
            }
        }

        public override bool CanSeek {
            get {
                return false;
            }
        }

        public override bool CanWrite {
            get {
                return fs.CanWrite;
            }
        }

        public override long Length {
            get {
                return fs.Length;
            }
        }

        public override long Position {
            get {
                return fs.Position;
            }

            set {
                fs.Position = value;
            }
        }
        */

        [Obsolete]
        private ConcurrentLogWriter() { }

        public ConcurrentLogWriter(string path, char columnSeparator = '\t') {
            this.columnSeparator = columnSeparator;
            this.AppendOrCreate(path);
            this.writeLock = new SemaphoreSlim(1, 1);
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
                fs.Flush();
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
                await fs.FlushAsync();
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
        }

        public async Task LogAsync(params string[] columns) {
            await this.LogAsync(columns as IEnumerable<string>);
        }

        public async Task LogAsync(IEnumerable<string> columns) {
            //StringBuilder logLine = new StringBuilder(DateTime.UtcNow.ToString("s", System.Globalization.CultureInfo.InvariantCulture));
            StringBuilder logLine = new StringBuilder(DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
            foreach (string c in columns) {
                logLine.Append(this.columnSeparator);
                if(c != null)
                    logLine.Append(c);
            }
            await this.WriteLineAsync(logLine.ToString());
        }

        /*
        public override int Read(byte[] buffer, int offset, int count) {
            throw new NotImplementedException();
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin) {
            throw new NotImplementedException();
        }

        public override void SetLength(long value) {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count) {
            try {
                fs.Write(buffer, offset, count);
            }
            catch {
                this.ReOpen();
                fs.Write(buffer, offset, count);
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
            try {
                return fs.WriteAsync(buffer, offset, count, cancellationToken);
            }
            catch {
                this.ReOpen();
                return fs.WriteAsync(buffer, offset, count, cancellationToken);
            }
        }
        */

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
