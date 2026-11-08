namespace EncryptLib;

/// <summary>
/// ファイルを暗号化するクラス
/// </summary>
/// <param name="key">暗号化鍵</param>
public class FileEncryptor(byte[] key) : Encryptor(key)
{
	/// <summary>
	/// 暗号化
	/// </summary>
	/// <param name="inputFilePath">入力ファイルパス</param>
	/// <param name="outputFilePath">出力ファイルパス</param>
	public void EncryptFile(string inputFilePath, string outputFilePath)
	{
		using FileStream inputStream = new FileStream(inputFilePath, FileMode.Open);
		using FileStream outputStream = new FileStream(outputFilePath, FileMode.Create);
		Encrypt(inputStream, outputStream);
	}

	/// <summary>
	/// 復号
	/// </summary>
	/// <param name="inputFilePath">入力ファイルパス</param>
	/// <param name="outputFilePath">出力ファイルパス</param>
	public void DecryptFile(string inputFilePath, string outputFilePath)
	{
		using FileStream inputStream = new FileStream(inputFilePath, FileMode.Open);
		using FileStream outputStream = new FileStream(outputFilePath, FileMode.Create);
		Decrypt(inputStream, outputStream);
	}
}
