using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace TokenRegistrationAPIService.Models
{
    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage code)
        {
            try
            {
                MailMessage mail = new MailMessage();
                mail.To.Add(code.Destination);
                mail.From = new MailAddress("abhijaiswal.abi@gmail.com");
                mail.Subject = code.Subject;
                mail.Body = code.Body;
                mail.Priority = MailPriority.High;
                SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
                client.EnableSsl = true;
                client.UseDefaultCredentials = false;
                client.Credentials = new NetworkCredential("abhijaiswal.abi@gmail.com", "traininsane");
                client.Send(mail);
                return Task.FromResult((int)HttpStatusCode.OK);
            }
            catch
            {
                return Task.FromResult((int)HttpStatusCode.InternalServerError);
            }
        }
    }
}