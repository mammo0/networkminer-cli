using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedUtils {
    public static class MathUtils {

        public static double GetMedian(double[] array) {
            return GetMedian(array, array.Length);
        }
        public static double GetMedian(IList<double> list) {
            return GetMedian(list, list.Count);
        }

        public static double GetMedian(IEnumerable<double> values, int size) {
            int middleIndex = (size - 1) / 2;//3 => 1, 4 => 1
            if (size % 2 == 0)//average of two middle numbers
                return values.OrderBy(x => x).Skip(middleIndex).Take(2).Average();
            else//odd number, take the middle one
                return values.OrderBy(x => x).ElementAt(middleIndex);
                
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <returns>A value between 0.0 (no entropy) and 8.0 (random)</returns>
        public static double GetEntropy(byte[] data, int offset, int length) {
            if (length < 1)
                return 0;

            double entropy = 0.0;
            int[] byteCount = new int[256];
            for (int i = 0; i < length; i++)
                byteCount[data[offset + i]]++;
            for (int i = 0; i < byteCount.Length; i++) {
                double byteFreq = (1.0 * byteCount[i]) / length;
                if (byteFreq > 0.0)
                    entropy -= byteFreq * Math.Log(byteFreq, 2);
            }
            return entropy;
        }

        //Similar to Log2
        public static byte CountBitsInMask(uint mask) {
            if (mask == 0)
                return 0;
            byte bits = 1;
            while (1 << bits < mask)
                bits++;
            return bits;
        }
    }
}
