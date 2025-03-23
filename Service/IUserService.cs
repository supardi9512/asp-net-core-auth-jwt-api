using DotnetAuth.Domain.Contracts;

namespace DotnetAuth.Service
{
    public interface IUserService
    {
        Task<UserResponse> RegisterAsync(UserRegisterRequest request);
        Task<UserResponse> LoginAsync(UserLoginRequest request);
        Task<UserResponse> GetByIdAsync(Guid id);
        Task<CurrentUserResponse> GetCurrentUserAsync();
        Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest request);
        Task<RevokeRefreshTokenResponse> RevokeRefreshTokenAsync(RefreshTokenRequest refreshTokenRemoveRequest);
        Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request);
        Task DeleteAsync(Guid id);
    }
}
