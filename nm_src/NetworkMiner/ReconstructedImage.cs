using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;

namespace NetworkMiner {
    internal class ReconstructedImage : IDisposable {

        private const int MAX_CACHED_PIXEL_COUNT = 40000;//200x200
        private Bitmap cachedBitmap = null;//lazy initialization to save memory
        private Size imageSize = Size.Empty;

        internal PacketParser.FileTransfer.ReconstructedFile ImageFile { get; }

        internal ReconstructedImage(PacketParser.FileTransfer.ReconstructedFile imageFile, Bitmap bitmap = null) {
            this.ImageFile = imageFile;
            if(bitmap != null)
                this.TrySetBitmap(bitmap);
        }
        

        private bool TrySetBitmap(Bitmap bitmap) {
            if (bitmap == null)
                return false;
            else if (bitmap.Size == Size.Empty)
                return false;
            else if (this.cachedBitmap == null && this.CountPixels(bitmap) <= MAX_CACHED_PIXEL_COUNT) {//the call to CountPixels will also set this.imageSize
                this.cachedBitmap = new Bitmap(bitmap);//so that the original bitmap can be disposed
                return true;
            }
            else
                return false;
        }

        internal string GetText() {
            Size _size = this.GetImageSize();
            return this.ImageFile.Filename + "\n" + _size.Width + "x" + _size.Height + ", " + this.ImageFile.FileSizeString;
        }
        internal int CountPixels(Bitmap bm = null) {
            Size size = this.GetImageSize(bm);
            return size.Width * size.Height;
        }

        internal Size GetImageSize(Bitmap bm = null) {
            if (this.imageSize != Size.Empty)
                return this.imageSize;
            else {
                if(bm != null)
                    this.imageSize = bm.Size;
                else
                    this.imageSize = this.GetBitmap().Size;
                return this.imageSize;
            }
        }

        internal Bitmap GetBitmap() {
            //this will consume memory, better to read it from disk when needed?
            if (this.cachedBitmap != null) {
                return this.cachedBitmap;
            }
            else {
                Bitmap _bm = new Bitmap(this.ImageFile.FilePath);
                this.TrySetBitmap(_bm);
                return _bm;
            }
        }

        internal bool TryGetCachedBitmap(out Bitmap bitmap) {
            if (this.cachedBitmap == null) {
                bitmap = null;
                return false;
            }
            else { 
                bitmap = this.cachedBitmap;
                return true;
            }
        }


        internal ListViewItem AddToImageListAndCreateListViewItem(ImageList imageList) {
            imageList.Images.Add(this.GetBitmap());
            return this.CreateListViewItem(imageList.Images.Count - 1);
        }

        internal ListViewItem CreateListViewItem(int imageIndex) {
            return new ListViewItem {
                Text = this.GetText(),
                Tag = this,
                ImageIndex = imageIndex,
                ToolTipText = this.GetDescription(),
            };
        }

        

        internal string GetDescription() {
            return "Source: " + this.ImageFile.SourceHost + "\nDestination: " + this.ImageFile.DestinationHost + "\nReconstructed file path: " + this.ImageFile.FilePath;
        }

        public void Dispose() {
            if (this.cachedBitmap != null)
                this.cachedBitmap.Dispose();
        }
    }
}
