/*
{
  "name":    "persistence_check",
  "author":  "William",
  "version": "1.2",
  "desc":    "Checks for SysUpd in HKCU Run and DataCache value under HKCU WindowsUpdate",
  "args":    []
}
*/

using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;

public class Module
{
    public static string Run(string[] args)
    {
        Dictionary<string, object> result = new Dictionary<string, object>();

        // 1) Check HKCU\Software\Microsoft\Windows\CurrentVersion\Run for SysUpd
        try
        {
            using (RegistryKey runKey = Registry.CurrentUser.OpenSubKey(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run", false))
            {
                bool hasSysUpd = (runKey != null && runKey.GetValue("SysUpd") != null);
                result["Run\\SysUpd_exists"] = hasSysUpd;
                if (hasSysUpd)
                {
                    result["Run\\SysUpd_value"] = runKey.GetValue("SysUpd").ToString();
                }
            }
        }
        catch (Exception ex)
        {
            result["Run\\SysUpd_error"] = ex.Message;
        }

        // 2) Check HKCU\Software\WindowsUpdate for DataCache value
        try
        {
            using (RegistryKey wuKey = Registry.CurrentUser.OpenSubKey(
                "Software\\WindowsUpdate", false))
            {
                bool hasCache = false;
                if (wuKey != null)
                {
                    string[] names = wuKey.GetValueNames();
                    for (int i = 0; i < names.Length; i++)
                    {
                        if (names[i] == "DataCache")
                        {
                            hasCache = true;
                            break;
                        }
                    }
                }
                result["WU\\DataCache_exists"] = hasCache;
                if (hasCache)
                {
                    result["WU\\DataCache_value"] = wuKey.GetValue("DataCache").ToString();
                }
            }
        }
        catch (Exception ex)
        {
            result["WU\\DataCache_error"] = ex.Message;
        }

        // Build JSON
        StringBuilder sb = new StringBuilder();
        sb.Append("{");
        bool first = true;
        foreach (KeyValuePair<string, object> kv in result)
        {
            if (!first) sb.Append(",");
            first = false;
            sb.Append("\"").Append(Escape(kv.Key)).Append("\":");
            object v = kv.Value;
            if (v is bool)
            {
                sb.Append(((bool)v) ? "true" : "false");
            }
            else
            {
                sb.Append("\"").Append(Escape(v.ToString())).Append("\"");
            }
        }
        sb.Append("}");
        return sb.ToString();
    }

    private static string Escape(string s)
    {
        return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }
}