/* 
{
  "name":    "messagebox",
  "author":  "William",
  "version": "1.1",
  "desc":    "Displays a Windows MessageBox with a custom message and title.",
  "args":    ["messageText", "titleText"]
}
*/
using System.Windows.Forms;

public class Module
{
    public static string Run(string[] args)
    {
        var text = args.Length > 0 ? args[0] : "Hello from C2!";
        var title = args.Length > 1 ? args[1] : "C2 Module Demo";
        var thread = new System.Threading.Thread(() =>
        {
            MessageBox.Show(
                text,
                title,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        });
        thread.SetApartmentState(System.Threading.ApartmentState.STA);
        thread.Start();
        thread.Join();
        return string.Format(
            "Displayed message: {0} (Title: {1})",
            text,
            title
        );
    }
}
