using System.Security.Cryptography;

namespace EncryptLib;

/// <summary>
/// IVを自動的に管理する暗号化処理
/// </summary>
public class Encryptor : IDisposable
{
	/// <summary>
	/// Dispose済みかどうか
	/// </summary>
	private bool _disposed;

	/// <summary>
	/// 暗号化対象アルゴリズム
	/// </summary>
	private readonly SymmetricAlgorithm alg;

	/// <summary>
	/// 暗号鍵生成用ハッシュアルゴリズム
	/// </summary>
	private readonly HashAlgorithmName hashAlgorithm;

	/// <summary>
	/// アルゴリズムの生成
	/// </summary>
	/// <returns>アルゴリズム</returns>
	private static SymmetricAlgorithm CreateAlgorithm()
	{
		SymmetricAlgorithm alg = Aes.Create();
		try
		{
			alg.Mode = CipherMode.CBC;
			alg.Padding = PaddingMode.PKCS7;
			return alg;
		}
		catch
		{
			alg.Dispose();
			throw;
		}
	}

	/// <summary>
	/// コンストラクタ
	/// </summary>
	public Encryptor() : this(HashAlgorithmName.SHA256)
	{
	}

	/// <summary>
	/// コンストラクタ
	/// </summary>
	/// <param name="hashAlgorithm">ハッシュアルゴリズム</param>
	public Encryptor(HashAlgorithmName hashAlgorithm)
	{
		alg = CreateAlgorithm();	   
		this.hashAlgorithm = hashAlgorithm;
	}

	/// <summary>
	/// コンストラクタ
	/// </summary>
	/// <param name="key">暗号化鍵</param>
	/// <param name="salt">ソルト</param>
	public Encryptor(byte[] key, byte[] salt) : this(key, salt, 100000)
	{
	}

	/// <summary>
	/// コンストラクタ
	/// </summary>
	/// <param name="key">暗号化鍵</param>
	/// <param name="salt">ソルト</param>
	/// <param name="iterations">PBKDF2の反復回数</param>
	/// <exception cref="ArgumentNullException">keyまたはsaltがnull</exception>
	/// <exception cref="ArgumentException">keyまたはsaltが空配列</exception>
	public Encryptor(byte[] key, byte[] salt, int iterations) : this()
	{
		ArgumentNullException.ThrowIfNull(key);
		ArgumentNullException.ThrowIfNull(salt);
		if (key.Length == 0)
		{
			throw new ArgumentException("key must not be empty.", nameof(key));
		}
		if (salt.Length == 0)
		{
			throw new ArgumentException("salt must not be empty.", nameof(salt));
		}

		int keySizeInBytes = alg.KeySize / 8;
		// PBKDF2で鍵を生成する。キーは流出する可能性があるので直接使用しない。
		alg.Key = Rfc2898DeriveBytes.Pbkdf2(key, salt, iterations, hashAlgorithm, keySizeInBytes);
	}

	/// <summary>
	/// 新しい鍵を作成する
	/// </summary>
	/// <returns>生成した新しい鍵</returns>
	public byte[] CreateKey()
	{
		alg.GenerateKey();
		return alg.Key;
	}

	/// <summary>
	/// 暗号化
	/// ファイルの暗号化であれば、本メソッドを直接呼び出す。
	/// </summary>
	/// <param name="input">入力</param>
	/// <param name="output">出力</param>
	public void Encrypt(Stream input, Stream output)
	{
		// 暗号化する度にIVを生成する。
		alg.GenerateIV();

		// IVは秘匿する必要が無いので、暗号化対象データの先頭に付与する。
		output.Write(alg.IV);

		using ICryptoTransform transform = alg.CreateEncryptor();
		using CryptoStream stream = new(output, transform, CryptoStreamMode.Write);
		input.CopyTo(stream);
	}

	/// <summary>
	/// バイト配列の暗号化
	/// </summary>
	/// <param name="data">暗号化対象データ</param>
	/// <returns>暗号化結果</returns>
	public byte[] Encrypt(byte[] data)
	{
		using MemoryStream input = new(data);
		using MemoryStream output = new();
		Encrypt(input, output);
		return output.ToArray();
	}

	/// <summary>
	/// 復号
	/// </summary>
	/// <param name="input">入力</param>
	/// <param name="output">出力</param>
	/// <exception cref="InvalidDataException">想定データではない</exception>
	public void Decrypt(Stream input, Stream output)
	{
		// IVのgetterはcloneを返すので、そのまま使える
		byte[] iv = alg.IV;
		// 入力の先頭に付与されているIVを読み込む。
		int read = input.Read(iv, 0, iv.Length);
		if (read != iv.Length)
		{
			throw new InvalidDataException();
		}
		// IVはsetterでセットする必要がある。
		alg.IV = iv;

		using ICryptoTransform transform = alg.CreateDecryptor();
		using CryptoStream stream = new(input, transform, CryptoStreamMode.Read);
		stream.CopyTo(output);
	}

	/// <summary>
	/// 復号
	/// </summary>
	/// <param name="data">複合対象データ</param>
	/// <returns>復号結果</returns>
	public byte[] Decrypt(byte[] data)
	{
		using MemoryStream input = new(data);
		using MemoryStream output = new();
		Decrypt(input, output);
		return output.ToArray();
	}

	/// <summary>
	/// Dispose
	/// </summary>
	public void Dispose()
	{
		if (_disposed)
		{
			// すでにDispose済みでもエラーにはしない
			return;
		}

		alg?.Dispose();
		_disposed = true;
		// ファイナライザはそもそも無いが、警告避け
		GC.SuppressFinalize(this);
	}
}
