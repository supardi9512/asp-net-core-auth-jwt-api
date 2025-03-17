using AutoMapper;
using Azure.Core;
using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace DotnetAuth.Service
{
    public class UserService : IUserService
    {
        private readonly ITokenService _tokenService;
        private readonly ICurrentUserService _currentUserService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;
        private readonly ILogger<UserService> _logger;

        public UserService(ITokenService tokenService, ICurrentUserService currentUserService, UserManager<ApplicationUser> userManager, IMapper mapper, ILogger<UserService> logger)
        {
            _tokenService = tokenService;
            _currentUserService = currentUserService;
            _userManager = userManager;
            _mapper = mapper;
            _logger = logger;
        }
        
        //a method to register a new user
        public async Task<UserResponse> RegisterAsync(UserRegisterRequest request)
        {
            _logger.LogInformation("Registering user");
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                _logger.LogError("Email already exists");
                throw new Exception("Email already exists");
            }

            var newUser = _mapper.Map<ApplicationUser>(request);

            // generate a unique username
            newUser.UserName = GenerateUserName(request.FirstName, request.LastName);
            var result = await _userManager.CreateAsync(newUser, request.Password);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Failed to create user: {errors}", errors);
                throw new Exception($"Failed to create user: {errors}");
            }
            _logger.LogInformation("User created successfully");
            await _tokenService.GenerateToken(newUser);
            return _mapper.Map<UserResponse>(newUser);
     
        }

        //this method generates a unique username by concatenating the first name and last name
        private string GenerateUserName(string firstName, string lastName)
        {
            var baseUsername = $"{firstName} {lastName}".ToLower();

            //check if the username already exists
            var username = baseUsername;
            var count = 1;
            while (_userManager.Users.Any(u => u.UserName == username))
            {
                username = $"{baseUsername}{count}";
                count++;
            }
            return username;
        }

        //a method to login a user
        public async Task<UserResponse> LoginAsync(UserLoginRequest request)
        {
            if(request == null)
            {
                _logger.LogError("Login request is null");
                throw new ArgumentNullException(nameof(request));
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                _logger.LogError("Invalid email or password");
                throw new Exception("Invalid email or password");
            }

            //generate access token
            var token = await _tokenService.GenerateToken(user);

            //generate refresh token
            var refreshToken = _tokenService.GenerateRefreshToken();

            //hash the refresh token and store it in the database or override the existing refresh token
            using var sha256 = SHA256.Create();
            var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
            user.RefreshToken = Convert.ToBase64String(refreshTokenHash);
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(2);

            //update user information in database
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Failed to update user: {errors}", errors);
                throw new Exception($"Failed to update user: {errors}");
            }

            var userResponse = _mapper.Map<ApplicationUser, UserResponse>(user);
            userResponse.AccessToken = token;
            userResponse.RefreshToken = refreshToken;

            return userResponse;
        }

        //get user by id
        public async Task<UserResponse> GetByIdAsync(Guid id)
        {
            _logger.LogInformation("Getting user by id");
            var user = await _userManager.FindByIdAsync(id.ToString());
            if(user == null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }
            _logger.LogInformation("User found");
            return _mapper.Map<UserResponse>(user);
        }

        //get current user
        public async Task<CurrentUserResponse> GetCurrentUserAsync()
        {
            var user = await _userManager.FindByIdAsync(_currentUserService.GetUserId());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }
            _logger.LogInformation("User found");
            return _mapper.Map<CurrentUserResponse>(user);
        }

        public async Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest request)
        {
            _logger.LogInformation("RefreshToken");

            //Hash the incoming RefreshToken and compare it with the one stored in the database
            using var sha256 = SHA256.Create();
            var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(request.RefreshToken));
            var hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

            //find user based on the refresh token
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
            if(user == null)
            {
                _logger.LogError("Invalid refresh token");
                throw new Exception("Invalid refresh token");
            }

            //validate the refresh token expiry time
            if(user.RefreshTokenExpiryTime < DateTime.Now)
            {
                _logger.LogWarning("Refresh token expired for the user ID: {UserId}", user.Id);
                throw new Exception("Refresh token expired");
            }

            //generate a new access token
            var newAccessToken = await _tokenService.GenerateToken(user);
            _logger.LogInformation("Access token generated successfully");
            var currentUserResponse = _mapper.Map<CurrentUserResponse>(user);
            currentUserResponse.AccessToken = newAccessToken;

            return currentUserResponse;
        }

        public async Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRemoveRequest)
        {
            _logger.LogInformation("Revoking refresh token");

            try
            {
                //Hash the refresh token
                using var sha256 = SHA256.Create();
                var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshTokenRemoveRequest.RefreshToken));
                var hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

                //find the user base on the refresh token
                var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
                if (user == null)
                {
                    _logger.LogError("Invalid refresh token");
                    throw new Exception("Invalid refresh token");
                }

                //validate the refresh token expiry time
                if (user.RefreshTokenExpiryTime < DateTime.Now)
                {
                    _logger.LogWarning("Refresh token expired for the user ID: {UserId}", user.Id);
                    throw new Exception("Refresh token expired");
                }

                //remove the refresh token
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;

                //update user information in database
                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    _logger.LogError("failed to update user");

                    return new RevokeRefreshTokenResponse
                    {
                        Message = "failed to revoke refresh token"
                    };
                }

                _logger.LogInformation("Refresh token revoked successfully");
                return new RevokeRefreshTokenResponse
                {
                    Message = "Refresh token revoked successfully"
                };

            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to revoke refresh token: {ex}", ex.Message);
                throw new Exception("Failed to revoke refresh token");
            }
        }

        public async Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }

            user.FirstName = request.FirstName;
            user.LastName = request.LastName;
            user.Email = request.Email;
            user.Gender = request.Gender;

            await _userManager.UpdateAsync(user);
            return _mapper.Map<UserResponse>(user);
        }

        public async Task DeleteAsync(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }
            await _userManager.DeleteAsync(user);
        }
    }
}
