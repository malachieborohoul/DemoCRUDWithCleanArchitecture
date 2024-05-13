using Application.DTOs;
using Application.DTOs.Request.Account;
using Application.DTOs.Response;
using Application.DTOs.Response.Account;

namespace Application.Contracts;

public interface IAccount
{
    Task CreateAdmin();
    Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model);
    Task<LoginResponse> LoginAccountAsync(LoginDTO model);
    Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model);
    Task<IEnumerable<GetRoleDTO>> GetRolesAsync();
    Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync();
    Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model);
}