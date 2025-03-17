using DotnetAuth.Domain.Contracts;

namespace DotnetAuth.Service
{
    public class IUserService
    {
        Task<UserResponse> RegisterAsync(UserRegisterRequest request);
        Task<CurrentUserResponse> GetCurrentUserAsync();
        Task<UserResponse> GetByIdAsync(Guid id);
        Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request);
        Task DeleteAsync(Guid id);
        Task<RevokeRefreshTokenResponse> RevokeRefreshTokenAsync(RefreshTokenRequest refreshTokenRemoveRequest);
        Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest request);
        Task<UserResponse> LoginAsync(UserLoginRequest request);
    }
}
