namespace EncryptLib.Test;

[TestClass]
public class TestPassword
{
	/// <summary>
	/// パスワードのハッシュ化と検証のテスト（正しいパスワード）
	/// </summary>
	[TestMethod]
	public void TestVerifyPassword1()
	{
		Password password = new();
		string originalPassword = "password";
		byte[] hashedPassword = password.HashPassword(originalPassword);
		string hashedPasswordBase64 = Convert.ToBase64String(hashedPassword);
		bool isVerified = password.VerifyPassword(originalPassword, hashedPassword);
		Assert.IsTrue(isVerified);
	}

	/// <summary>
	/// パスワードのハッシュ化と検証のテスト（間違ったパスワード）
	/// </summary>
	[TestMethod]
	public void TestVerifyPassword2()
	{
		Password password = new();
		string originalPassword = "password";
		byte[] hashedPassword = password.HashPassword(originalPassword);
		bool isVerifiedWrong = password.VerifyPassword("Password", hashedPassword);
		Assert.IsFalse(isVerifiedWrong);
	}

	[TestMethod]
	public void TestHashPassword()
	{
		Password password = new();
		string originalPassword = "password";
		List<byte[]> hashedPasswords = new();
		for (int i = 0; i < 10; i++)
		{
			byte[] hashedPassword = password.HashPassword(originalPassword);
			Assert.IsNotNull(hashedPassword);
			hashedPasswords.Add(hashedPassword);
			// ハッシュ化した結果は毎回異なることを確認
			for (int j = 0; j < i; j++)
			{
				Assert.AreNotEqual(Convert.ToBase64String(hashedPassword), Convert.ToBase64String(hashedPasswords[j]));
			}
		}
	}
}
