using System;
using System.IO;
using System.Threading.Tasks;

namespace NetworkMiner
{
    public static class FileUtils
    {
        public static async Task<bool> DeleteDirectory(string directoryPath, int maxRetries = 10, int millisecondsDelay = 30)
        {
            if (directoryPath == null)
                throw new ArgumentNullException(directoryPath);
            if (maxRetries < 1)
                throw new ArgumentOutOfRangeException(nameof(maxRetries));
            if (millisecondsDelay < 1)
                throw new ArgumentOutOfRangeException(nameof(millisecondsDelay));

            for (int i = 0; i < maxRetries; ++i) {
                try {
                    // try to delete the directory if it exists
                    if (Directory.Exists(directoryPath))
                        Directory.Delete(directoryPath, true);

                    return true;
                } catch (IOException) {  // System.IO.IOException: The directory is not empty
                    await Task.Delay(millisecondsDelay);
                } catch (UnauthorizedAccessException) {
                    await Task.Delay(millisecondsDelay);
                }
            }

            return false;
        }
    }
}
