using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.Contracts;
using Application.DTOs;
using Application.DTOs.Request.Account;
using Application.DTOs.Response;
using Application.DTOs.Response.Account;
using Application.Extensions;
using Domain.Entity.Authentication;
using Mapster;
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


        private async Task<GeneralResponse> AssignUserToRole(ApplicationUser user, IdentityRole role)
        {
            if (user is null || role is null) return new GeneralResponse(false, "Model state cannot be empty");
            if (await FindRoleByNameAsync(role.Name) == null)
                //Mapter to map
                await CreateRoleAsync(role.Adapt(new CreateRoleDTO()));
            IdentityResult result = await userManager.AddToRoleAsync(user, role.Name);
            string error = CheckResponse(result);
            if (!string.IsNullOrEmpty(error))
                return new GeneralResponse(false, error);
            else
                return new GeneralResponse(true, $"{user.Name} assigned to {role.Name} role");
        }


        private static string CheckResponse(IdentityResult result)
        {
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(_ => _.Description);
                return string.Join(Environment.NewLine, errors);
            }

            return null!;
        }


    #endregion
    
    
    public async Task CreateAdmin()
    {
        try
        {
            if (await FindRoleByNameAsync(Constant.Role.Admin) != null) return;
            var admin = new CreateAccountDTO()
            {
                Name = "Admin",
                Password = "Admin",
                EmailAddress = "admin@admin.com",
                Role = Constant.Role.Admin
            };
            await CreateAccountAsync(admin);
        }
        catch (Exception e)
        {
           
        }
    }

    public async Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model)
    {
        try
        {
            if (await FindUserByEmailAsync(model.EmailAddress) != null)
                return new GeneralResponse(false, "Sorry, user is already created");
            var user = new ApplicationUser()
            {
                Name = model.Name,
                UserName = model.EmailAddress,
                Email = model.EmailAddress,
                PasswordHash = model.Password
            };
            var result = await userManager.CreateAsync(user, model.Password);
            string error = CheckResponse(result);
            if (!string.IsNullOrEmpty(error))
                return new GeneralResponse(false, error);
            var (flag, message) = await AssignUserToRole(user, new IdentityRole() { Name = model.Role });

            return new GeneralResponse(flag, message);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<LoginResponse> LoginAccountAsync(LoginDTO model)
    {
        try
        {
            //Check if email exists
            var user = await FindUserByEmailAsync(model.EmailAddress);
            if (user is null)
                return new LoginResponse(false, "User not found");
            SignInResult result;
            
            //If it exists

            try
            {
                result = await signInManager.CheckPasswordSignInAsync(user, model.Password, false); 
            }
            catch (Exception e)
            {
                return new LoginResponse(false, "Invalid credentials");
            }
            
            // Password doesnt match
            if (!result.Succeeded)
                return new LoginResponse(false, "Invalid credentials");
            
            //Password match

            string jwtToken = await GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            
            if (string.IsNullOrEmpty(jwtToken) || string.IsNullOrEmpty(refreshToken))
                return new LoginResponse(false, "Error occured while logging in account, please contact administration");
            else
                return new LoginResponse(true, $"{user.Name} successfully logged in", jwtToken, refreshToken);




        }
        catch (Exception e)
        {
            return new LoginResponse(false, e.Message);
        }
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