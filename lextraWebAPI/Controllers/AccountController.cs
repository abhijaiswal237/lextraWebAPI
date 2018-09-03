using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Web;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using lextraWebAPI.Models;
using lextraWebAPI.Providers;
using lextraWebAPI.Results;
using System.Text;
using System.Data.Entity;
using System.IO;
using LitJson;
using System.Linq;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Text.RegularExpressions;

namespace lextraWebAPI.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName(),
                HasRegistered = externalLogin == null,
                LoginProvider = externalLogin?.LoginProvider
            };
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
                ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);
            
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/AddExternalLogin
        [Route("AddExternalLogin")]
        public async Task<IHttpActionResult> AddExternalLogin(AddExternalLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            AuthenticationTicket ticket = AccessTokenFormat.Unprotect(model.ExternalAccessToken);

            if (ticket == null || ticket.Identity == null || (ticket.Properties != null
                && ticket.Properties.ExpiresUtc.HasValue
                && ticket.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow))
            {
                return BadRequest("External login failure.");
            }

            ExternalLoginData externalData = ExternalLoginData.FromIdentity(ticket.Identity);

            if (externalData == null)
            {
                return BadRequest("The external login is already associated with an account.");
            }

            IdentityResult result = await UserManager.AddLoginAsync(User.Identity.GetUserId(),
                new UserLoginInfo(externalData.LoginProvider, externalData.ProviderKey));

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RemoveLogin
        [Route("RemoveLogin")]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                
                 ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser() { UserName = model.UserName, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            using (lextraDBEntities entities = new lextraDBEntities())
            {
                UserInfo userinfo = await entities.UserInfoes.FirstOrDefaultAsync(u => u.Email == model.Email);
                userinfo.FirstName = model.FirstName;
                userinfo.LastName = model.LastName;
                userinfo.ZipCode = model.ZipCode;
                //entities.UserInfoes.Add(userinfo);
                entities.SaveChanges();
            }

            return Ok();
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("AvailableUsername")]
        public async Task<IHttpActionResult> AvailableUsernameAsync(string username)
        {
            var regexItem = new Regex("^[a-zA-Z0-9_]*$");
            if (username.Length < 4 || username.Length > 15 || !regexItem.IsMatch(username))
            {
                return BadRequest();
            }
            ApplicationUser user = await UserManager.FindByNameAsync(username);
            if (user != null)
            {
                return Conflict();
            }
            return Ok();
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("VerifyZip")]
        public string VerifyZip(string zip)
        {
            try
            {
                string userAuthenticationURI = "https://www.zipcodeapi.com/rest/auGRQBNcLYtvVb4T5Dc81nTu8l4hH6puwPtm9Jct3q8T9ADaWhmVHHLWkQYQUg30/info.json/" + zip + "/radians";
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(userAuthenticationURI);
                request.Method = "GET";
                request.ContentType = "application/json";
                WebResponse response = request.GetResponse();
                string responce = "";
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    var ApiStatus = reader.ReadToEnd();
                    JsonData data = JsonMapper.ToObject(ApiStatus);
                    string city = data["city"].ToString();
                    string state = data["state"].ToString();
                    responce = city + ", " + state;
                }
                return responce;
            }
            catch
            {
                return "Cannot Locate";
            }
        }

        public bool IsValidEmail(string emailaddress)
        {
            try
            {
                MailAddress m = new MailAddress(emailaddress);

                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("AvailableEmail")]
        public async Task<IHttpActionResult> AvailableEmailAsync(string email)
        {
            try
            {
                int index = email.IndexOf("@");
                string sub = email.Substring(index);
                if (!IsValidEmail(email) || !sub.Contains('.'))
                {
                    return BadRequest();
                }
                ApplicationUser user = await UserManager.FindByEmailAsync(email);
                if (user != null)
                {
                    return Conflict();
                }
                return Ok();
            }
            catch
            {
                return BadRequest();
            }
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("AvailableResetEmail")]
        public async Task<IHttpActionResult> AvailableResetEmailAsync(string email)
        {
            try
            {
                int index = email.IndexOf("@");
                string sub = email.Substring(index);
                if (!IsValidEmail(email) || !sub.Contains('.'))
                {
                    return BadRequest();
                }
                ApplicationUser user = await UserManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return Conflict();
                }
                return Ok();
            }
            catch
            {
                return InternalServerError();
            }
        }

        public static string GetHashSha256(string text, string salt)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(string.Concat(text, salt));
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            string hashString = string.Empty;
            foreach (byte x in hash)
            {
                hashString += String.Format("{0:x2}", x);
            }
            return hashString;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("ValidateEmail")]
        public async Task<IHttpActionResult> ValidateEmailAsync(RegisterAndValidateEmailBindingModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
                var user = new ApplicationUser() { UserName = model.Username, Email = model.Email };

                // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                var guid = Guid.NewGuid().ToString().Substring(0, Guid.NewGuid().ToString().IndexOf("-"));

                string code = GetHashSha256(guid, user.Id);
                using (lextraDBEntities entities = new lextraDBEntities())
                {
                    UserInfo userinfo = await entities.UserInfoes.FirstOrDefaultAsync(u => u.Email == model.Email);
                    if (userinfo != null)
                        entities.UserInfoes.Remove(userinfo);
                    UserInfo userdata = new UserInfo
                    {
                        UserName = model.Username,
                        Email = model.Email,
                        UserID = user.Id,
                        Code = code,
                        Verified = "false"
                    };
                    entities.UserInfoes.Add(userdata);
                    entities.SaveChanges();
                }
                SendEmail(user.Email, "Confirm your account", $"Your OTP for Email Confirmation is {guid}");
                return Ok(user.Id);
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        public static void SendEmail(string Email, string Subject, string Body)
        {
            MailMessage mail = new MailMessage();
            mail.To.Add(Email);
            mail.From = new MailAddress("abhijaiswal.abi@gmail.com");
            mail.Subject = Subject;
            mail.Body = Body;
            mail.Priority = MailPriority.High;
            SmtpClient client = new SmtpClient("smtp.gmail.com", 587)
            {
                EnableSsl = true,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential("abhijaiswal.abi@gmail.com", "traininsane")
            };
            client.Send(mail);
        }

        //[AllowAnonymous]
        //[HttpPost]
        //[Route("UpdateBeforeLogin")]
        //public async Task<IHttpActionResult> UpdateBeforeLogin(UpdateBeforeLoginBindingModel model)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }
        //    using (lextraDBEntities entities = new lextraDBEntities())
        //    {
        //        UserInfo userinfo = await entities.UserInfoes.FirstOrDefaultAsync(u => u.UserName == model.UserName);
        //        userinfo.FirstName = model.FirstName;
        //        userinfo.LastName = model.LastName;
        //        userinfo.ZipCode = model.ZipCode;
        //        entities.SaveChanges();
        //        return Ok();
        //    }
        //}

        [HttpPost]
        [AllowAnonymous]
        [Route("ForgotPassword")]
        public async Task<IHttpActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var user = await UserManager.FindByEmailAsync(model.Email);
                    //If user has to activate his email to confirm his account, the use code listing below
                    //if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                    //{
                    //    return Ok();
                    //}
                    if (user == null)
                    {
                        return BadRequest();
                    }

                    // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    var guid = Guid.NewGuid().ToString();
                    string code = GetHashSha256(guid, model.Email);
                    using (lextraDBEntities entities = new lextraDBEntities())
                    {
                        lextraResetPassword userinfo = await entities.lextraResetPasswords.FirstOrDefaultAsync(u => u.Email == model.Email);
                        if (userinfo != null)
                            entities.lextraResetPasswords.Remove(userinfo);
                        lextraResetPassword userdata = new lextraResetPassword
                        {
                            Email = model.Email,
                            Code = code
                        };
                        entities.lextraResetPasswords.Add(userdata);
                        entities.SaveChanges();
                    }
                    var callbackUrl = "http://localhost:52576/Account/ResetPassword?code=" + guid;
                    var body = new StringBuilder();
                    body.Append("Please reset your password by clicking ");
                    body.Append(@"<a href=\""" + callbackUrl + "\">here</a");
                    SendEmail(user.Email, "Reset Password for LEXREWARDS", body.ToString());
                    return Ok();
                }

                // If we got this far, something failed, redisplay form
                return BadRequest(ModelState);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("ResetPassword")]
        public async Task<IHttpActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return Ok();
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return Ok();
            }
            return Ok();
        }


        [HttpGet]
        [AllowAnonymous]
        [Route("ConfirmEmail")]
        public async Task<IHttpActionResult> ConfirmEmail(string userId = "", string code = "")
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
            {
                ModelState.AddModelError("", "User Id and Code are required");
                return BadRequest(ModelState);
            }

            //IdentityResult result = await UserManager.ConfirmEmailAsync(userId, code);

            using (lextraDBEntities entities = new lextraDBEntities())
            {
                UserInfo userinfo = new UserInfo();
                userinfo = await entities.UserInfoes.FirstOrDefaultAsync(u => u.UserID == userId);
                string match = GetHashSha256(code, userId);

                if (userinfo.Code == match)
                    userinfo.Verified = "true";
                else
                {
                    return BadRequest();
                }
                //entities.UserInfoes.Add(userinfo);
                entities.SaveChanges();
            }
            return Ok();
        }


        // POST api/Account/RegisterExternal
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var info = await Authentication.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return InternalServerError();
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result); 
            }
            return Ok();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider)
                };

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
    }
}
