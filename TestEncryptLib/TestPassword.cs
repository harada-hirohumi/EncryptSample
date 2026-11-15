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
}
