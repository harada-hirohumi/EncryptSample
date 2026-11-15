using System.Security.Cryptography;

namespace EncryptLib;

/// <summary>
/// パスワードのハッシュ化と検証を行うクラス
/// </summary>
public class Password
{
	/// <summary>
	/// デフォルトの反復回数
	/// </summary>
	private const int DefaultIterations = 10000;

	/// <summary>
	/// デフォルトのソルトサイズ
	/// </summary>
	private const int DefaultSaltSize = 32;

	/// <summary>
	/// ハッシュアルゴリズム
	/// </summary>
	private readonly HashAlgorithmName algorithm;

	/// <summary>
	/// ソルトのサイズ
	/// </summary>
	private readonly int saltSize; 

	/// <summary>
	/// 反復回数
	/// </summary>
	private readonly int iterations;

	/// <summary>
	/// ハッシュのバイトサイズ
	/// </summary>
	private readonly int hashSizeInBytes;

	/// <summary>
	/// コンストラクタ
	/// </summary>
	/// <param name="hashAlgorithm">ハッシュアルゴリズム</param>
	/// <param name="saltSize">ソルトのサイズ</param>
	/// <param name="iterations">反復回数</param>
	/// <exception cref="ArgumentException">サポートしていないアルゴリズム</exception>
	public Password(HashAlgorithmName hashAlgorithm, int saltSize, int iterations)
	{
		algorithm = hashAlgorithm;
		this.saltSize = saltSize;
		this.iterations = iterations;
		hashSizeInBytes = hashAlgorithm.Name switch
		{
			"MD5" => hashSizeInBytes = 16,
			"SHA1" => hashSizeInBytes = 20,
			"SHA256" => hashSizeInBytes = 32,
			"SHA384" => hashSizeInBytes = 48,
			"SHA512" => hashSizeInBytes = 64,
			_ => throw new ArgumentException("Unsupported hash algorithm", nameof(hashAlgorithm)),
		};
	}


	/// <summary>
	/// コンストラクタ
	/// </summary>
	/// <param name="hashAlgorithm">ハッシュアルゴリズム</param>
	public Password(HashAlgorithmName hashAlgorithm) : this(hashAlgorithm, DefaultSaltSize, DefaultIterations)
	{
	}

	/// <summary>
	/// デフォルトコンストラクタ
	/// </summary>
	public Password() : this(HashAlgorithmName.SHA256)
	{
	}

	/// <summary>
	/// パスワードのハッシュ
	/// </summary>
	/// <param name="password">パスワード</param>
	/// <returns>ハッシュ</returns>
	public byte[] HashPassword(string password)
	{
		byte[] salt = RandomNumberGenerator.GetBytes(saltSize);
		byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, algorithm, hashSizeInBytes);

		Span<byte> result = new byte[saltSize + hash.Length];
		salt.CopyTo(result);
		hash.CopyTo(result[saltSize..]);	
		return result.ToArray();
	}

	/// <summary>
	/// パスワードの検証
	/// </summary>
	/// <param name="password">検証対象パスワード</param>
	/// <param name="hashedPassword">ハッシュ化されたパスワード</param>
	/// <returns>検証結果</returns>
	public bool VerifyPassword(string password, byte[] hashedPassword)
	{
		Span<byte> salt = hashedPassword.AsSpan(0, saltSize);

		byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, algorithm, hashSizeInBytes);

		// 比較の為の時間を一定にするため、CryptographicOperations.FixedTimeEqualsを使用する。
		return CryptographicOperations.FixedTimeEquals(hash, hashedPassword.AsSpan(saltSize, hash.Length));
	}
}
