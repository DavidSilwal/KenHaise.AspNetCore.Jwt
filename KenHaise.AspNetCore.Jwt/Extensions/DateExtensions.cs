using System;
using System.Collections.Generic;
using System.Text;

namespace KenHaise.AspNetCore.Jwt.Extensions
{
    static class DateExtensions
    {
        public static Int64 ToTimeStamp(this DateTime date) => Convert.ToInt64(Math.Round((date.ToUniversalTime() -
                               new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
                              .TotalSeconds));
        public static DateTime FromTimeStamp(this Int64 timeStamp, bool converToLocalTime = false)
        {
            DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var time = dtDateTime.AddSeconds(timeStamp);
            return converToLocalTime ? time.ToLocalTime() : time;
        }
    }
}
