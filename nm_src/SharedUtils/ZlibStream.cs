using System;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace SharedUtils {
    public class ZlibStream : System.IO.Stream, IDisposable {
        //argh! ZLibStream requires .NET 7 or later!
        //But zlib can be parsed as gzip by replacing the first 2 bytes (78 01) with:
        //1f8b 0800 0000 0000 0000
        //The window size (wbits) might be a problem though, due to window headers/trailers?

        /**
         * Zlib header
         * 78 01 - No Compression/low
         * 78 9C - Default Compression
         * 78 DA - Best Compression 
         * ^  ^
         * |  |
         * |   ´--
         *  `-----78 = deflate compression with 32K window size
         **/

        public static readonly byte[] ZLIB_HEADER = { 0x78, 0x01 };


        /**
         * Gzip header
         * 1f 8b = Magic
         *    08 = DEFLATE
         **/
        public static readonly byte[] GZIP_HEADER = { 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        private readonly ArraySegmentStream gzipInputStream;
        private readonly System.IO.Compression.GZipStream gzipOutputStream;


        public ZlibStream() {
            this.gzipInputStream = new ArraySegmentStream();
            this.gzipInputStream.Write(GZIP_HEADER, 0, GZIP_HEADER.Length);
            this.gzipOutputStream = new GZipStream(this.gzipInputStream, CompressionMode.Decompress);
        }

        public override bool CanRead {
            get {
                return this.gzipOutputStream.CanRead;
            }
        }

        public override bool CanSeek {
            get {
                return false;
            }
        }

        public override bool CanWrite {
            get {
                return this.gzipInputStream.CanWrite;
            }
        }

        public override long Length {
            get {
                throw new NotImplementedException();
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
            this.gzipInputStream?.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count) {
            return this.gzipOutputStream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin) {
            throw new NotImplementedException();
        }

        public override void SetLength(long value) {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count) {
            if (this.gzipInputStream.Length == GZIP_HEADER.Length) {
                if (buffer[0] == ZLIB_HEADER[0]) {
                    offset += ZLIB_HEADER.Length;
                    count -= ZLIB_HEADER.Length;
                }
                else {
                    throw new ArgumentException("Input buffer must be ZLIB compressed");
                }
            }
            if (count > 0) {
                this.gzipInputStream.Write(buffer, offset, count);
            }
        }

        public new void Dispose() {
            this.gzipOutputStream?.Dispose();
            this.gzipInputStream?.Dispose();
            base.Dispose();
        }
    }
}
