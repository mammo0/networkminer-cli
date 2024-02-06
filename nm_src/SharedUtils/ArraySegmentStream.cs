using System;
using System.Collections.Generic;
using System.IO;

namespace SharedUtils {
    internal class ArraySegmentStream : Stream {
        private readonly List<ArraySegment<byte>> segments;
        private long bytesWritten = 0;

        internal ArraySegmentStream() : base() {
            this.segments = new List<ArraySegment<byte>>();
        }
        public override bool CanRead {
            get => true;
        }

        public override bool CanSeek {
            get => false;
        }

        public override bool CanWrite {
            get => true;
        }

        public override long Length {
            get {
                return this.bytesWritten;
            }
        }
        public override long Position {
            get {
                throw new NotImplementedException();
            }

            set {
                throw new NotImplementedException();
            }
        }

        public override void Flush() {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count) {
            int bytesRead = 0;
            while(this.segments.Count > 0 && this.segments[0].Count <= count - bytesRead) {
                //read all bytes from first segment and remove it
                ArraySegment<byte> first = this.segments[0];
                Array.Copy(first.Array, first.Offset, buffer, offset + bytesRead, first.Count);
                this.segments.RemoveAt(0);
                bytesRead += first.Count;
            }
            if (count > bytesRead && this.segments.Count > 0 && this.segments[0].Count > count - bytesRead) {
                ArraySegment<byte> first = this.segments[0];
                //remove some bytes from first segment
                Array.Copy(first.Array, first.Offset, buffer, offset + bytesRead, count - bytesRead);
                this.segments[0] = new ArraySegment<byte>(first.Array, first.Offset + count - bytesRead, first.Count - count + bytesRead);
                bytesRead = count;
            }
            return bytesRead;
        }

        public override long Seek(long offset, SeekOrigin origin) {
            throw new NotImplementedException();
        }

        public override void SetLength(long value) {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count) {
            if (count > 0) {
                this.segments.Add(new ArraySegment<byte>(buffer, offset, count));
                this.bytesWritten += count;
            }
        }
    }
}
