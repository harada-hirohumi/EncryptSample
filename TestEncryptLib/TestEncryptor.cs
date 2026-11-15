using System.Text;

namespace EncryptLib.Test;

[TestClass]
public sealed class TestEncryptor
{
	[TestMethod]
	public void Test()
	{
		Encryptor encryptor = new();
		byte[] key = encryptor.CreateKey();
		Assert.IsNotNull(key);
	}


	/// <summary>
	/// 暗号化と復号化のテスト
	/// </summary>
	[TestMethod]
	public void TestEncryptDecrypt()
	{
		Encryptor encryptor = new();
		byte[] key = encryptor.CreateKey();

		string originalText = "Hello, World!";
		byte[] originalData = Encoding.UTF8.GetBytes(originalText);

		byte[] encryptedData = encryptor.Encrypt(originalData);
		Assert.IsNotNull(encryptedData);
		Assert.AreNotEqual(originalData, encryptedData);

		byte[] decryptedData = encryptor.Decrypt(encryptedData);
		Assert.IsNotNull(decryptedData);
		Assert.AreEqual(originalText, Encoding.UTF8.GetString(decryptedData));
	}
}
