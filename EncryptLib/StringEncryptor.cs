using System.Text;

namespace EncryptLib;

/// <summary>
/// 文字列の暗号化クラス。
/// </summary>
/// <param name="encoding">エンコーディング</param>
/// <param name="key">暗号鍵</param>
public class StringEncryptor(Encoding encoding, byte[] key) : Encryptor(key)
{
	private readonly Encoding encoding = encoding;

	/// <summary>
	/// コンストラクタ
	/// </summary>
	/// <param name="key">暗号鍵</param>
	public StringEncryptor(byte[] key) : this(Encoding.UTF8, key)
	{
		
	}

	/// <summary>
	/// 文字列の暗号化
	/// </summary>
	/// <param name="value">暗号化する文字列</param>
	/// <returns>暗号化結果のBase64表現</returns>
	public string EncyptString(string value)
	{
		byte[] data = Encrypt(encoding.GetBytes(value));
		return Convert.ToBase64String(data);
	}

	/// <summary>
	/// 文字列の復号
	/// </summary>
	/// <param name="value">復号対象</param>
	/// <returns>復号結果</returns>
	public string DecryptString(string value)
	{
		byte[] data = Decrypt(Convert.FromBase64String(value));
		return encoding.GetString(data);
	}
}
