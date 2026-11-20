using System.Text;

namespace EncryptLib;

/// <summary>
/// 文字列の暗号化クラス。
/// </summary>
/// <param name="encoding">エンコーディング</param>
/// <param name="key">暗号鍵</param>
/// <param name="salt">ソルト</param>
public class StringEncryptor(Encoding encoding, byte[] key, byte[] salt) : Encryptor(key, salt)
{
	/// <summary>
	/// デフォルトのエンコーディング
	/// </summary>
	private static 	readonly Encoding DefaultEncoding = Encoding.UTF8;

	/// <summary>
	/// エンコーディング
	/// </summary>
	private readonly Encoding Encoding = encoding;

	/// <summary>
	/// コンストラクタ
	/// </summary>
	/// <param name="key">暗号鍵</param>
	/// <param name="salt">ソルト</param>
	public StringEncryptor(byte[] key, byte[] salt) : this(DefaultEncoding, key, salt)
	{
		
	}

	/// <summary>
	/// 文字列の暗号化
	/// </summary>
	/// <param name="value">暗号化する文字列</param>
	/// <returns>暗号化結果のBase64表現</returns>
	public string EncyptString(string value)
	{
		byte[] data = Encrypt(Encoding.GetBytes(value));
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
		return Encoding.GetString(data);
	}
}
