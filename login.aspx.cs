using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Data;
using System.Data.SqlClient;
using System.Configuration;
using log4net;

namespace ASPLab.Account
{
    public partial class Login : System.Web.UI.Page
    {
        private readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void LoginButton_Click(object sender, EventArgs e)
        {
            DoLogin();
            //DoLogin_BCrypt();
        }

        protected void DoLogin()
        {
            StringBuilder html = new StringBuilder();

            string constr = ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

            using (var conn = new SqlConnection(constr))
            {
                conn.Open();

                using (var cmd = new SqlCommand(@" select * from users where username='" + Username.Text + "' ", conn))
                {
                    SqlDataReader dr = cmd.ExecuteReader();
                    if (dr.HasRows && dr.Read())
                    {
                        String passwordFromDatabase = dr["password"].ToString();
                        if (String.Equals(passwordFromDatabase, Password.Text))
                        {
                            Session["isLoggedIn"] = 1;
                            Session["username"] = Username.Text;
                            Session["user_id"] = dr["id"];
                            Response.Write(dr["id"]);
                            RedirectionAfterLogin();
                            //RedirectionAfterLogin_F();
                        }
                        else
                        {
                            html.Append("<b style='color:red'>Invalid credentials</b>");
                            LoginFormPage.Controls.Add(new Literal { Text = html.ToString() });
                            return;
                        }

                    }
                    else
                    {
                        html.Append("<b style='color:red'>Invalid credentials</b>");
                        LoginFormPage.Controls.Add(new Literal { Text = html.ToString() });
                        return;
                    }

                }
            }
        }

        protected void DoLogin_BCrypt()
        {
            StringBuilder html = new StringBuilder();

            string constr = ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

            using (var conn = new SqlConnection(constr))
            {
                conn.Open();

                using (var cmd = new SqlCommand(@" select * from users where username='" + Username.Text + "' ", conn))
                {
                    SqlDataReader dr = cmd.ExecuteReader();
                    if(dr.HasRows && dr.Read())
                    {
                        String hashFromDatabase = dr["password"].ToString();
                        if (BCrypt.Net.BCrypt.Verify(Password.Text, hashFromDatabase))
                        {
                            Session["isLoggedIn"] = 1;
                            Session["username"] = Username.Text;
                            Session["user_id"] = dr["id"];
                            RedirectionAfterLogin();
                            //RedirectionAfterLogin_F();
                        }
                        else
                        {
                            html.Append("<b style='color:red'>Invalid credentials</b>");
                            LoginFormPage.Controls.Add(new Literal { Text = html.ToString() });
                            return;
                        }

                    }
                    else
                    {
                        html.Append("<b style='color:red'>Invalid credentials</b>");
                        LoginFormPage.Controls.Add(new Literal { Text = html.ToString() });
                        return;
                    }
                    
                }
            }
        }

        public void RedirectionAfterLogin()
        {
            if (!String.IsNullOrEmpty(Request.QueryString["returnUrl"]))
            {
                Response.Redirect(Request.QueryString["returnUrl"]);
            }
            else
            {
                Response.Redirect("~/");
            }
        }

        public void RedirectionAfterLogin_F()
        {
            if (!String.IsNullOrEmpty(Request.QueryString["returnUrl"]) && IsLocalUrl(Request.QueryString["returnUrl"]))
            {
                Response.Redirect(Request.QueryString["returnUrl"]);
            }
            else
            {
                Response.Redirect("~/");
            }
        }

        protected void Application_OnPostAuthenticateRequest(object sender, EventArgs e)
        {
            
            var authCookie = Request.Cookies["Auth"];
            if (authCookie != null && !string.IsNullOrEmpty(authCookie.Value))
            {
                var identity = new ClaimsIdentity(
                    new[]
                    {
                        new Claim(ClaimTypes.Name, authCookie.Value)
                    }, "ApplicationCookie");
                var user = new ClaimsPrincipal(identity);
                Thread.CurrentPrincipal = user;
                HttpContext.Current.User = user;
            }
        }

        public ActionResult Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // insecure auth
            if (!model.Username.Equals(model.Password, StringComparison.InvariantCultureIgnoreCase) ||
                Accounts.List.All(x => x.Username != model.Username))
            {
                ModelState.AddModelError("Password", "Invalid username or password.");
                return View(model);
            }

            Response.Cookies.Add(new HttpCookie("Auth", model.Username));
            return RedirectToLocal(returnUrl);
        }

        protected void ButtonLogOn_Click(object sender, EventArgs e)
        {
            string email = txtUserName.Text;
            string pwd = txtPassword.Text;

            log.Info("User " + email + " attempted to log in with password " + pwd);

            if (!du.IsValidCustomerLogin(email, pwd))
            {
                labelError.Text = "Incorrect username/password"; 
                PanelError.Visible = true;
                return;
            }
            // put ticket into the cookie
            FormsAuthenticationTicket ticket =
                        new FormsAuthenticationTicket(
                            1, //version 
                            email, //name 
                            DateTime.Now, //issueDate
                            DateTime.Now.AddDays(14), //expireDate 
                            true, //isPersistent
                            "customer", //userData (customer role)
                            FormsAuthentication.FormsCookiePath //cookiePath
            );

            string encrypted_ticket = FormsAuthentication.Encrypt(ticket); //encrypt the ticket

            // put ticket into the cookie
            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted_ticket);

            //set expiration date
            if (ticket.IsPersistent)
                cookie.Expires = ticket.Expiration;
                
            Response.Cookies.Add(cookie);
            
            string returnUrl = Request.QueryString["ReturnUrl"];
            
            if (returnUrl == null) 
                returnUrl = "/MainPage.aspx";
                
            Response.Redirect(returnUrl);        
        }

        

        private bool IsLocalUrl(string url)
        {
            /**
             * Validating URL & allowing only local redirection
             */
 
            // From: https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/preventing-open-redirection-attacks

            if (string.IsNullOrEmpty(url))
            {
                return false;
            }
            else
            {
                return ((url[0] == '/' && (url.Length == 1 ||
                        (url[1] != '/' && url[1] != '\\'))) ||   // "/" or "/foo" but not "//" or "/\"
                        (url.Length > 1 &&
                         url[0] == '~' && url[1] == '/'));   // "~/" or "~/foo"
            }
        }
    }
}
