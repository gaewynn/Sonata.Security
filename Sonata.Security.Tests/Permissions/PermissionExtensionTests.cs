using alice.tuprolog;
using Sonata.Security.Permissions;
using Xunit;

namespace Sonata.Security.Tests.Permissions
{
    public class PermissionExtensionTests
    {
        [Fact]
        public void AsTermReturnsUnderscoreIfArgIsNull()
        {
            var expected = Term.createTerm("_");
            var actual = ((string) null).AsTerm();

            Assert.Equal(expected.toString(), actual.toString());
        }

        [Fact]
        public void AsTermReturnsUnderscoreIfArgIsEmpty()
        {
            var expected = Term.createTerm("_");
            var actual = "".AsTerm();

            Assert.Equal(expected.toString(), actual.toString());
        }

        [Fact]
        public void AsTermReturnsTermIfArgIsNotEmpty()
        {
            var expected = Term.createTerm("xyz");
            var actual = "xyz".AsTerm();

            Assert.Equal(expected.toString(), actual.toString());
        }

        [Fact]
        public void AsQuotedStringPropagatesNull()
        {
            var actual = ((string)null).AsQuotedString();

            Assert.Null(actual);
        }

        [Fact]
        public void AsQuotedStringReturnsNullWhenArgIsWhitespace()
        {
            var actual = " \t\r\n".AsQuotedString();

            Assert.Null(actual);
        }

        [Fact]
        public void AsQuotedStringSurroundsStringWithSingleQuotes()
        {
            var actual = "test".AsQuotedString();

            Assert.Equal(@"'test'", actual);
        }

    }
}
