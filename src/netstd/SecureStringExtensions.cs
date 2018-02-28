namespace Sable.HMAC
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;

    public static class SecureStringExtensions
    {
        public static SecureString FromByteArray(this byte[] bytes, Encoding encoding)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));

            return encoding.GetChars(bytes).FromCharArray(encoding);
        }

        public static SecureString FromCharArray(this char[] chars, Encoding encoding)
        {
            if (chars == null) throw new ArgumentNullException(nameof(chars));
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));

            var secStr = new SecureString();
            for (int i = 0; i < chars.Length; i++) secStr.AppendChar(chars[i]);
            secStr.MakeReadOnly();

            return secStr;
        }

        public static unsafe byte[] ToByteArray(this SecureString secStr, Encoding encoding)
        {
            if (secStr == null) throw new ArgumentNullException(nameof(secStr));
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));

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

                // zero buffers
                ((IntPtr)chars).ZeroMem(strLen);
                ((IntPtr)bptr).ZeroMem(len);

                return arr;
            }
            finally
            {
                if (str != IntPtr.Zero) Marshal.ZeroFreeBSTR(str);
                if (bytes != IntPtr.Zero) Marshal.FreeHGlobal(bytes);
            }
        }

        public static SecureString ToSecureString(this string str)
        {
            var secStr = new SecureString();
            for (int i = 0; i < str.Length; i++) secStr.AppendChar(str[i]);
            secStr.MakeReadOnly();

            return secStr;
        }

        private static SecureString AppendChar(SecureString ss, char c)
        {
            ss.AppendChar(c);
            return ss;
        }

        private static SecureString MakeReadOnly(SecureString ss)
        {
            ss.MakeReadOnly();
            return ss;
        }
    }
}