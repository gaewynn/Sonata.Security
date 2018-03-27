using alice.tuprolog;
using System;
using System.Collections.Generic;
using System.Text;

namespace Sonata.Security.Permissions
{
    public static class PermissionExtensions
    {
        public static Term AsTerm(this string value)
        {
            return Term.createTerm(string.IsNullOrEmpty(value) ? "_" : value);
        }

        public static string AsQuotedString(this string value)
        {
            return string.IsNullOrWhiteSpace(value) ? null : $"'{value}'";
        }
    }
}
