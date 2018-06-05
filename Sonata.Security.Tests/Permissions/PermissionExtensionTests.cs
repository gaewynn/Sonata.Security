using Sonata.Core.Extensions;
using Sonata.Security.Extensions;
using Xunit;

namespace Sonata.Security.Tests.Permissions
{
	public class PermissionExtensionTests
	{
		public PermissionExtensionTests()
		{
			SecurityProvider.Configure(true);
		}

		[Fact]
		public void AsTermReturnsUnderscoreIfArgIsNull()
		{
			const string expected = "_";
			var actual = ((string) null).AsPrologConstant();

			Assert.Equal(expected, actual);
		}

		[Fact]
		public void AsTermReturnsUnderscoreIfArgIsEmpty()
		{
			const string expected = "_";
			var actual = "".AsPrologConstant();

			Assert.Equal(expected, actual);
		}

		[Fact]
		public void AsTermReturnsTermIfArgIsNotEmpty()
		{
			const string expected = "\"xyz\"";
			var actual = "xyz".AsPrologConstant();

			Assert.Equal(expected, actual);
		}

		[Fact]
		public void AsQuotedStringPropagatesNull()
		{
			var actual = ((string)null).Quote();

			Assert.Null(actual);
		}

		[Fact]
		public void AsQuotedStringSurroundsStringWithSingleQuotes()
		{
			var actual = "test".Quote();

			Assert.Equal(@"'test'", actual);
		}

		[Fact]
		public void AsDoubleQuotedStringPropagatesNull()
		{
			var actual = ((string)null).Quote();

			Assert.Null(actual);
		}

		[Fact]
		public void AsDoubleQuotedStringSurroundsStringWithSingleQuotes()
		{
			var actual = "test".DoubleQuote();

			Assert.Equal("\"test\"", actual);
		}

	}
}
