namespace ShareLoader.ClickNLoad.Models;

using System.ComponentModel.DataAnnotations;

public class ItemModel
{
    public string Name { get; set; }
    public string Id { get; set; }
    public string Downloader { get; set; }
    public int Size { get; set; }
    public bool IsOnline { get; set; }
}