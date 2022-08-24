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

    string links = "";

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

        //RijndaelManaged rDel = new RijndaelManaged();
        //System.Text.ASCIIEncoding aEc = new System.Text.ASCIIEncoding();

        jk = jk.ToUpper();
        string decKey = "";
        for (int i = 0; i < jk.Length; i += 2)
        {
            decKey += (char)Convert.ToUInt16(jk.Substring(i, 2), 16);
        }

        /*rDel.Key = aEc.GetBytes(decKey);
        rDel.IV = aEc.GetBytes(decKey);
        rDel.Mode = CipherMode.CBC;

        rDel.Padding = PaddingMode.None;
        ICryptoTransform cTransform = rDel.CreateDecryptor();
        byte[] resultArray = cTransform.TransformFinalBlock(dataByte, 0, dataByte.Length);
        string rawLinks = aEc.GetString(resultArray);*/
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
        rgx = new Regex("\n+");
        links = rgx.Replace(rawLinks, "\r\n");

        Process.Start("http://localhost:9666/flash/check");

        return Ok();
    }

    public IActionResult check() 
    {
        return View(links);
    }
}
