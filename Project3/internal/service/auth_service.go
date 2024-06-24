package service

import (
	"Ticketing/entity"
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// LoginUseCase interface untuk login
type LoginUseCase interface {
	Login(ctx context.Context, email string, password string) (*entity.User, error)
}

// LoginRepository interface untuk mendapatkan user berdasarkan email
type LoginRepository interface {
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
}

// loginService struct yang mengimplementasikan LoginUseCase
type loginService struct {
	repository LoginRepository
}

// NewLoginService membuat instance baru dari loginService
func NewLoginService(repository LoginRepository) *loginService {
	return &loginService{
		repository: repository,
	}
}

// Login method untuk melakukan pengecekan email dan password
func (s *loginService) Login(ctx context.Context, email string, password string) (*entity.User, error) {
	// Mendapatkan user berdasarkan email dari repository
	user, err := s.repository.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	// Memeriksa apakah user dengan email tersebut ada
	if user == nil {
		return nil, errors.New("user with that email not found")
	}

	// Memverifikasi kata sandi menggunakan bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, errors.New("incorrect login credentials")
	}

	// Mengembalikan user jika email dan kata sandi cocok
	return user, nil
}

// register
type RegistrationUseCase interface {
	Registration(ctx context.Context, user *entity.User) error
}

type RegistrationRepository interface {
	Registration(ctx context.Context, user *entity.User) error
	// GetByEmail(ctx context.Context, email string) (*entity.User, error)
}

type registrationService struct {
	repository RegistrationRepository
}

func NewRegistrationService(repository RegistrationRepository) *registrationService {
	return &registrationService{
		repository: repository,
	}
}

func (s *registrationService) Registration(ctx context.Context, user *entity.User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashedPassword)
	return s.repository.Registration(ctx, user)
}

// BuyerCreateAccount
type BuyerCreateAccountUseCase interface {
	BuyerCreateAccount(ctx context.Context, user *entity.User) error
}

type BuyerCreateAccountRepository interface {
	BuyerCreateAccount(ctx context.Context, user *entity.User) error
}

type buyercreateaccountService struct {
	repository BuyerCreateAccountRepository
}

func NewBuyerCreateAccountService(repository BuyerCreateAccountRepository) *buyercreateaccountService {
	return &buyercreateaccountService{
		repository: repository,
	}
}

// func (s *buyercreateaccountService) BuyerCreateAccount(ctx context.Context, user *entity.User) error {
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		return err
// 	}

// 	user.Password = string(hashedPassword)
// 	return s.repository.BuyerCreateAccount(ctx, user)
// }
