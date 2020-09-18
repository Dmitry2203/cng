// testcpp3.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <algorithm>

#pragma comment (lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

using std::string;
using std::vector;
using std::mutex;
using std::stringstream;
using std::runtime_error;
using std::exception;
using std::cout;
using std::endl;

// @brief Реализация механизма шифрования/расширования.
class CryptoProviderCNG final
{
public:
  virtual ~CryptoProviderCNG();
  CryptoProviderCNG();

  // @brief Зашифровать данные.
  vector<BYTE> Crypt(const vector<BYTE>& data, bool bEncrypt = true) const;

protected:
  // @brief Инициализация класса - загрузка контекста и ключа.
  void Init(void);

  // @brief Деинициализация класса - удаление контекста и ключа.
  void Uninit(void);

private:
  BCRYPT_ALG_HANDLE _hAESAlg{nullptr};
  BCRYPT_KEY_HANDLE _hKey{nullptr};
  vector<BYTE> vKeyObject;
};

CryptoProviderCNG::CryptoProviderCNG(void)
{
	Init();
}

CryptoProviderCNG::~CryptoProviderCNG(void)
{
	Uninit();
}

void CryptoProviderCNG::Init(void)
{
	try
	{
    NTSTATUS  status{ 0 };
    stringstream str;

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&_hAESAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
      str << "BCryptOpenAlgorithmProvider error code: " << status;
      throw runtime_error(str.str());
    }

    DWORD cbKeyObject{ 0 };
    DWORD cbData{ 0 };
    if (!NT_SUCCESS(status = BCryptGetProperty(_hAESAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) {
      str << "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) error code: " << status;
      throw runtime_error(str.str());
    }

    DWORD cbBlockLen{ 0 };
    if (!NT_SUCCESS(status = BCryptGetProperty(_hAESAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0))) {
      str << "BCryptGetProperty(BCRYPT_BLOCK_LENGTH) error code: " << status;
      throw runtime_error(str.str());
    }

    if (!NT_SUCCESS(status = BCryptSetProperty(_hAESAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
      str << "BCryptGetProperty(BCRYPT_CHAINING_MODE) error code: " << status;
      throw runtime_error(str.str());
    }
        
    vector<BYTE> rgbAES128Key(16);
    std::generate(rgbAES128Key.begin(), rgbAES128Key.end(), [n = 0]() mutable { return n += 3; });

    vKeyObject.resize(cbKeyObject);

    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(_hAESAlg, &_hKey, vKeyObject.data(), cbKeyObject, rgbAES128Key.data(), rgbAES128Key.size(), 0))) {
      str << "BCryptGenerateSymmetricKey error code: " << status;
      throw runtime_error(str.str());
    }
	}
	catch (std::exception& ex)
	{
    stringstream str;
		str << "CryptoProviderCNG::Init: " << ex.what() << "!" << endl;
		throw runtime_error(str.str());
	}
	catch (...)
	{
		throw runtime_error("CryptoProviderCNG::Init: Unknown error!");
	}
}

void CryptoProviderCNG::Uninit(void)
{
  NTSTATUS  status{0};
  if (_hAESAlg != nullptr) {
    status = BCryptCloseAlgorithmProvider(_hAESAlg, 0);
  }      
  if (_hKey != nullptr) {
      status = BCryptDestroyKey(_hKey);
  }
}

vector<BYTE> CryptoProviderCNG::Crypt(const vector<BYTE>& data, bool bEncrypt) const
{
	try
	{
    NTSTATUS  status{0};
    DWORD cbCipherText{0};

    stringstream str;
    vector<BYTE> vResult;

    if (bEncrypt)
    {
      DWORD cbCipherText = 0;
      if (!NT_SUCCESS(status = BCryptEncrypt(_hKey, const_cast<PUCHAR>(data.data()), data.size(), nullptr, nullptr, 0, nullptr, 0, &cbCipherText, BCRYPT_BLOCK_PADDING)))
      {
        str << "BCryptEncrypt 1 error code: " << status;
        throw runtime_error(str.str());
      }

      vResult.resize(cbCipherText);

      if (!NT_SUCCESS(status = BCryptEncrypt(_hKey, const_cast<PUCHAR>(data.data()), data.size(), nullptr, nullptr, 0, vResult.data(), cbCipherText, &cbCipherText, BCRYPT_BLOCK_PADDING))) {
        str << "BCryptEncrypt 2 error code: " << status;
        throw runtime_error(str.str());
      }
    }
    else
    {
      if (!NT_SUCCESS(status = BCryptDecrypt(_hKey, const_cast<PUCHAR>(data.data()), data.size(), nullptr, nullptr, 0, nullptr, 0, &cbCipherText, BCRYPT_BLOCK_PADDING))) {
        str << "BCryptDecrypt 1 error code: " << status;
        throw runtime_error(str.str());
      }

      vResult.resize(cbCipherText);
      if (!NT_SUCCESS(status = BCryptDecrypt(_hKey, const_cast<PUCHAR>(data.data()), data.size(), nullptr, nullptr, 0, vResult.data(), cbCipherText, &cbCipherText, BCRYPT_BLOCK_PADDING))) {
        str << "BCryptDecrypt 2 error code: " << status;
        throw runtime_error(str.str());
      }
      vResult.resize(cbCipherText);
    }
    return vResult;
  }
	catch (exception& ex)
	{
		std::stringstream str; 
    str << "CryptoProviderCNG::Crypt: [" << ex.what() << "] " << "!" << endl;
		throw runtime_error(str.str());
	}
	catch (...)
	{
		throw runtime_error("CryptoProviderCNG::Crypt: Unknown error!");
	}
}

int main()
{
  try
  {    
    vector<BYTE> v = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    auto crypto_provider = std::make_shared<CryptoProviderCNG>();
    auto crypted = crypto_provider->Crypt(v);
    auto encrypted = crypto_provider->Crypt(crypted, false);
  }
  catch (exception& ex)
  {
    cout << "Exception: " << ex.what() << endl;
  }

  return 0;
}