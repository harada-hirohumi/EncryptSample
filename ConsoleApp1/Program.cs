using System.Text;
using EncryptLib;

Console.WriteLine("Hello, World!");

// このような形で、鍵を生成しておく
//Encryptor encryptor = new Encryptor();
//byte[] key = encryptor.CreateKey();
//String encodedKey = Convert.ToBase64String(key);
//Console.WriteLine(encodedKey);

string encodedKey = "e/HpdTfyirkmq3LJKxKgebr40wvjJt/OlGUy6wue770=";
using StringEncryptor encryptor = new(Encoding.UTF8, Convert.FromBase64String(encodedKey));

string soure = "日本語";

List<string> encodedList = [];

// 10回暗号化して、全て異なる結果になる
for(int i = 0; i < 10; i++)
{
	string encoded = encryptor.EncyptString(soure);
	Console.WriteLine(encoded);
	encodedList.Add(encoded);
}

// 復号したら、元の値になる
foreach(string value in encodedList)
{
	string decoded = encryptor.DecryptString(value);
	Console.WriteLine(decoded);
}

// ファイルの暗号化
using FileEncryptor fileEncryptor = new(Convert.FromBase64String(encodedKey));
fileEncryptor.EncryptFile(@"C:\samples\abc.txt", @"C:\samples\abc.enc");
fileEncryptor.DecryptFile(@"C:\samples\abc.enc", @"C:\samples\abc.dec.txt");
