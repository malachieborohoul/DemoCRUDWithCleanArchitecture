using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.Contracts;
using Application.DTOs;
using Application.DTOs.Request.Account;
using Application.DTOs.Response;
using Application.DTOs.Response.Account;
using Domain.Entity.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Repos;

public class AccountRepository(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager, IConfiguration config, SignInManager<ApplicationUser> signInManager):IAccount
{
    #region Add often used methods

        private async Task<ApplicationUser> FindUserByEmailAsync(string email) => await userManager.FindByEmailAsync(email);
        private async Task<IdentityRole> FindRoleByNameAsync(string roleName) => await roleManager.FindByNameAsync(roleName);
        private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        
        private async Task<string> GenerateToken(ApplicationUser user)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var userClaims = new[]
                {
                    new Claim(ClaimTypes.Name, user.Name!),
                    new Claim(ClaimTypes.Email, user.Email!),
                    new Claim(ClaimTypes.Role, (await userManager.GetRolesAsync(user)).FirstOrDefault().ToString()),
                    new Claim("Fullname", user.Name),

                };
                var token = new JwtSecurityToken(
                    issuer: config["Jwt:Issuer"],
                    audience: config["Jwt:Audience"],
                    claims: userClaims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: credentials

                );
                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch
            {
                return null!;
            }
        }


    #endregion
    
    
    public async Task CreateAdmin()
    {
        throw new NotImplementedException();
    }

    public async Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model)
    {
        throw new NotImplementedException();
    }

    public async Task<LoginResponse> LoginAccountAsync(LoginDTO model)
    {
        throw new NotImplementedException();
    }

    public async Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model)
    {
        throw new NotImplementedException();
    }

    public async Task<IEnumerable<GetRoleDTO>> GetRolesAsync()
    {
        throw new NotImplementedException();
    }

    public async Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync()
    {
        throw new NotImplementedException();
    }

    public async Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model)
    {
        throw new NotImplementedException();
    }
}