using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace KenHaise.AspNetCore.Jwt
{
    class JwtSetting
    {
        public SecurityKey SecretKey { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
    }
}
