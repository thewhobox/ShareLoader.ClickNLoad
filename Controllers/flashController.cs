using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ShareLoader.ClickNLoad.Models;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace ShareLoader.ClickNLoad.Controllers;

public class flashController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public flashController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    static CheckViewModel model;

    public IActionResult addcrypted2()
    {
        string jk = Request.Form["jk"];
        jk = jk.Substring(jk.IndexOf('\'') + 1);
        jk = jk.Substring(0, jk.IndexOf('\''));
        string passwords = Request.Form["passwords"];
        string source = Request.Form["source"];
        string package = Request.Form["package"];
        string crypted = Request.Form["crypted"];

        byte[] dataByte = Convert.FromBase64String(crypted);

        jk = jk.ToUpper();
        string decKey = "";
        for (int i = 0; i < jk.Length; i += 2)
        {
            decKey += (char)Convert.ToUInt16(jk.Substring(i, 2), 16);
        }

        string rawLinks = "";

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = System.Text.Encoding.ASCII.GetBytes(decKey);
            aesAlg.IV = System.Text.Encoding.ASCII.GetBytes(decKey);
            aesAlg.Padding = PaddingMode.None;
            aesAlg.Mode = CipherMode.CBC;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(dataByte))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        rawLinks = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        Regex rgx = new Regex("\u0000+$");
        rawLinks = rgx.Replace(rawLinks, "");
        string[] links = rawLinks.Split("\r\n");



        model = new CheckViewModel() { 
            Name = package,
            RawLinks = string.Join(",", links),
            RawLinksCount = links.Count()
        };

        var ps = new ProcessStartInfo("http://localhost:9666/flash/check")
        { 
            UseShellExecute = true, 
            Verb = "open" 
        };
        Process.Start(ps);

        return Ok();
    }

    public IActionResult check() 
    {
        return View(model);
    }
}
