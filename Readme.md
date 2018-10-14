# Ken Haise Asp.Net Core Token Handler

KenHaise.AspNetCore.Jwt provides a way to generate basic bearer token with required claims. It's easy to setup with Asp.net core Identity. 

## Generating New Token

### Step 1: Create Project

Create Asp.net core 2.1 project with Individual User Accounts.

### Step 2: Add KenHaise.AspNetCore.Jwt

Install the package using package manager console

```
Install-Package KenHaise.AspNetCore.Jwt
```

Or using dot net CLI

```
dotnet add package KenHaise.AspNetCore.Jwt
```

### Step 3: Add JSON Configuration

Add following json in appsettings.json

```json
"Bearer": {
    "SecretKey": "your secret key",
    "Issuer": "your issuer",
    "Audience": "your audience"
  }
```

### Step 4: Setup Token Handler in Startup.cs

Add following code snippet in startup.cs in method ConfigureServices

```c#
//Adds database context with Sql Server
services.AddDbContext<ApplicationDbContext>(options =>
	options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));
//Adding Identity with DbContext
services.AddDefaultIdentity<IdentityUser>()
	.AddEntityFrameworkStores<ApplicationDbContext>();
//Adding JwtBearer with TokenHandler
services.AddAuthentication()
	.AddJwtBearerWithTokenHandler<IdentityUser>(JwtBearerDefaults.AuthenticationScheme, jwtOptions =>
	{
		jwtOptions.TokenValidationParameters = new TokenValidationParameters
		{
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ClockSkew = TimeSpan.Zero,
			ValidIssuer = Configuration.GetSection("Bearer:Issuer").Value,
			ValidAudience = Configuration.GetSection("Bearer:Audience").Value,
			IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.ASCII.GetBytes(Configuration.GetSection("Bearer:SecretKey").Value)),
        };
        jwtOptions.IncludeErrorDetails = true;
        jwtOptions.SaveToken = true;
    },expiry:DateTime.Now.AddDays(3));
```

### Step 5: Get ITokenHandler from DI

Create an account controller and get ITokenHandler from Dependency Injection.

```c#
private readonly UserManager<IdentityUser> _userManager;
private readonly SignInManager<IdentityUser> _signInManager;
private readonly ITokenHandler<IdentityUser> _tokenHandler;
//Getting ITokenHandler from DI
public AccountController(UserManager<IdentityUser> userManager,
                         SignInManager<IdentityUser> signInManager,
                         ITokenHandler<IdentityUser> tokenHandler)
{
    _userManager = userManager;
    _signInManager = signInManager;
    _tokenHandler = tokenHandler;
}
```

### Step 6: Create Login and Signup Actions

Create Login and signup action.

```C#
[HttpPost("[action]")]
public async Task<IActionResult> SignIn([FromBody] LoginModel model)
{
    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null)
    {
        ModelState.AddModelError("email", $"No user exists with email {model.Email}");
        return BadRequest(ModelState);
    }
    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
    if (result.Succeeded)
    {
        //Getting token with specified claims.
        var token = await _tokenHandler.GenerateTokenForUser(user, claims =>
                {
                    claims.Add(new Claim(ClaimTypes.Email, user.Email));
                },expiry: DateTime.Now.AddDays(5));
        return Ok(new { token, user.UserName });
    }
    ModelState.AddModelError("password", $"Invalid password");
    return BadRequest(ModelState);
}
```

```C#
[HttpPost("[action]")]
public async Task<IActionResult> Register([FromBody] RegisterModel model)
{
    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user != null)
    {
        ModelState.AddModelError("email", $"User already exists with email {model.Email}");
        return BadRequest(ModelState);
    }
    var myuser = new IdentityUser { UserName = model.UserName, Email = model.Email };
    var SignUpresult = await _userManager.CreateAsync(myuser, model.Password);
    if (SignUpresult.Succeeded)
    {
        return Ok(new { data = "Signup successful" });
    }
    ModelState.AddModelError("username", $"Username {model.UserName} is taken");
    return BadRequest(ModelState);
}
```

### Step 7: Test

Test the api by signing up and then logging in using POSTMAN.

## Refreshing a Token

Create an action method to allow refreshing an existing token.  Using the same ITokenHandler, you can use authorization header to generate new token or pass token string. 

### Using Token String

```C#
            //passing token string
			if (Request.Headers.TryGetValue("Authorization", out StringValues authorizationToken))
            {
                var token = authorizationToken.ToString().Split("Bearer ")[1];
                var newToken = await _tokenHandler.RefreshTokenAsync(token, DateTime.Now.AddDays(2));
                return Ok(new
                {
                    token = newToken
                });
            }
            return Unauthorized();
```

### Using Authorization Header

```C#
var newToken = await _tokenHandler.RefreshTokenAsync(Request.Headers["Authorization"], DateTime.Now.AddDays(2));
            return Ok(new
            {
                token = newToken
            });
```

The service takes care of separating token string from the header.  