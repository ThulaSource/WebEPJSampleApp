using System;
using System.Collections.Generic;
using System.Linq;

namespace HelseId.Common.Extensions
{
    public static class StringExtensions
    {
        public static bool IsNotNullOrEmpty(this String text)
        {
            return !string.IsNullOrEmpty(text);
        }

        public static bool IsNullOrEmpty(this String text)
        {
            return string.IsNullOrEmpty(text);
        }

        public static String[] FromSpaceSeparatedToList(this String spaceSeparatedList)
        {
            return spaceSeparatedList.Split(' ');
        }

        public static string ToSpaceSeparatedList(this List<String> list)
        {
            return string.Join(" ", list);
        }

        public static string ToSpaceSeparatedList(this String[] list)
        {
            return string.Join(" ", list);
        }
    }
}
