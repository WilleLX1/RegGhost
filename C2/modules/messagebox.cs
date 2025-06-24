/* 
{
  "name":    "messagebox",
  "author":  "William",
  "version": "1.0",
  "desc":    "Displays a Windows MessageBox",
  "args":    ["messageText"]
}
*/
using System.Windows.Forms;

public class Module
{
    public static string Run(string[] args)
    {
        var text = args.Length > 0 ? args[0] : "Hello from C2!";
        MessageBox.Show(
            text, 
            "C2 Module Demo", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Information
        );
        return "Displayed message: " + text;
    }
}
