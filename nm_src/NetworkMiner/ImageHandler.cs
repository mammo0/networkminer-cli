using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NetworkMiner {
    internal class ImageHandler {
        private const int DEFAULT_IMAGE_DIMENSION = 64;
        private static readonly Size DEFAULT_IMAGE_SIZE = new Size(DEFAULT_IMAGE_DIMENSION, DEFAULT_IMAGE_DIMENSION);
        private const int MIN_ZOOM_LEVEL = 10;
        private static readonly int MAX_ZOOM_LEVEL = 100 * 256 / DEFAULT_IMAGE_DIMENSION;


        private List<ReconstructedImage> reconstructedImages;
        private ImageList imageList;
        private int zoomLevel = 100;
        private string activeFilenameFilter = null;
        private int activeMinPixelsFilter = 0;
        private ListView parentListView;
        

        internal int ZoomLevel {
            get {
                return this.zoomLevel;
            }
            set {
                if (value != this.zoomLevel) {
                    if (value < MIN_ZOOM_LEVEL)
                        this.ZoomLevel = MIN_ZOOM_LEVEL;
                    else if (value > MAX_ZOOM_LEVEL)
                        this.ZoomLevel = MAX_ZOOM_LEVEL;
                    else {
                        this.zoomLevel = value;
                        this.SetImageSize(new Size(DEFAULT_IMAGE_SIZE.Width * this.zoomLevel / 100, DEFAULT_IMAGE_SIZE.Height * this.zoomLevel / 100));
                    }

                }
            }
        }
        internal ToolInterfaces.IColorHandler<System.Net.IPAddress> IpColorHandler { get; set; }

        internal int ImageCount {
            get {
                return this.reconstructedImages.Count;
            }
        }

        internal ImageHandler(System.Windows.Forms.ListView parentListView) {
            this.parentListView = parentListView;

            this.imageList = new ImageList {
                ImageSize = DEFAULT_IMAGE_SIZE,
                ColorDepth = ColorDepth.Depth32Bit
            };

            parentListView.LargeImageList = this.imageList;
            parentListView.View = View.LargeIcon;

            this.reconstructedImages = new List<ReconstructedImage>();
        }

        

        internal void AddImages(IEnumerable<Tuple<PacketParser.FileTransfer.ReconstructedFile, Bitmap>> imageTuples) {
            List<ListViewItem> newItems = new List<ListViewItem>();
            foreach ((PacketParser.FileTransfer.ReconstructedFile file, Bitmap bitmap) in imageTuples) {
                //NetworkMinerForm creates a new Bitmap from the original one, not sure if that's needed
                //this.imageList.Images.Add(new Bitmap(bitmapImage));//I do the new in order to release the file handle for the original file
                ReconstructedImage image = new ReconstructedImage(file, bitmap);
                this.reconstructedImages.Add(image);
                if(image.TryGetCachedBitmap(out Bitmap cachedBitmap))
                    this.imageList.Images.Add(cachedBitmap);
                else
                    this.imageList.Images.Add(new Bitmap(bitmap));//So that the original bitmap can be disposed

                if (this.Matches(image, this.activeMinPixelsFilter, this.activeFilenameFilter))
                    newItems.Add(this.GetListViewItem(this.reconstructedImages.Count - 1));
            }
            if (newItems.Count > 0 && this.parentListView != null)
                this.parentListView.Items.AddRange(newItems.ToArray());
        }

        internal void ResetZoomLevel() {
            this.SetImageSize(DEFAULT_IMAGE_SIZE);
        }

        

        /// <summary>
        /// Make sure to set Visible = false in parent ListView before calling SetImageSize()
        /// </summary>
        /// <param name="size"></param>
        private void SetImageSize(Size size) {
            if (this.imageList.ImageSize != size) {
                //we need to clear image list and re-add every image after changing the size
                this.imageList.Images.Clear();
                this.imageList.ImageSize = size;
                for (int i = 0; i < this.reconstructedImages.Count; i++) {
                    this.imageList.Images.Add(this.reconstructedImages[i].GetBitmap());
                }
            }
        }

        private ListViewItem[] GetListViewItems(int minPixels, string filenameFilter) {
            this.activeMinPixelsFilter = minPixels;
            this.activeFilenameFilter = filenameFilter;
            List<ListViewItem> itemList = new List<ListViewItem>();
            for(int i = 0; i < this.reconstructedImages.Count; i++) {
                if(this.Matches(this.reconstructedImages[i], minPixels, filenameFilter)) {
                    itemList.Add(this.GetListViewItem(i));
                }
            }
            return itemList.ToArray();
        }

        private ListViewItem GetListViewItem(int index) {
            ReconstructedImage image = this.reconstructedImages[index];
            var item = image.CreateListViewItem(index);
            if (this.IpColorHandler != null) {
                this.IpColorHandler.Colorize(image.ImageFile.SourceHost.IPAddress, item);
                this.IpColorHandler.Colorize(image.ImageFile.DestinationHost.IPAddress, item);
            }
            return item;
        }

        private bool Matches(ReconstructedImage image, int minPixels, string filenameFilter) {
            if (image.CountPixels() >= minPixels) {
                if (string.IsNullOrEmpty(filenameFilter) || image.ImageFile.Filename.Contains(filenameFilter)) {
                    return true;
                }
            }
            return false;
        }

        internal void UpdateImagesInListView(int zoomLevelPercent, int minPixels = 0, string filenameFilter = null) {
            this.parentListView.Visible = false;
            //listView.Clear();
            this.parentListView.Items.Clear();

            this.ZoomLevel = zoomLevelPercent;

            this.parentListView.LargeImageList = this.imageList;
            this.parentListView.View = View.LargeIcon;
            this.parentListView.Items.AddRange(this.GetListViewItems(minPixels, filenameFilter));

            this.parentListView.Visible = true;
            this.parentListView.Select();
        }

        internal void Clear() {
            this.imageList.Images.Clear();
            this.reconstructedImages.Clear();
            this.parentListView.Clear();
        }
    }
}
