﻿using System.Text.RegularExpressions;

namespace CryptomatorApi.Core
{
    public sealed class Wildcard : Regex
    {
        public Wildcard(string wildCardPattern)
            : base(WildcardPatternToRegex(wildCardPattern), RegexOptions.IgnoreCase)
        {
        }

        private static string WildcardPatternToRegex(string wildcardPattern)
        {
            string patternWithWildcards = "^" + Escape(wildcardPattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
            return patternWithWildcards;
        }
    }
}
