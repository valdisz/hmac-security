namespace Security.HMAC
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;

    internal static class SecureStringExtensions
    {
        public static unsafe byte[] ToByteArray(this SecureString secStr, Encoding encoding)
        {
            int strLen = secStr.Length;

            IntPtr bytes = IntPtr.Zero;
            IntPtr str = IntPtr.Zero;

            try
            {
                bytes = Marshal.AllocHGlobal(strLen);
                str = Marshal.SecureStringToBSTR(secStr);

                char* chars = (char*) str.ToPointer();
                byte* bptr = (byte*) bytes.ToPointer();
                int len = encoding.GetBytes(chars, strLen, bptr, strLen);

                byte[] arr = new byte[len];
                Marshal.Copy((IntPtr) bptr, arr, 0, len);

                return arr;
            }
            finally
            {
                if (str != IntPtr.Zero) Marshal.ZeroFreeBSTR(str);
                if (bytes != IntPtr.Zero) Marshal.FreeHGlobal(bytes);
            }
        }
    }
}