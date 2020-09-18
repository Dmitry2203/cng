#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <functional>
#include <chrono>
#include <ctime>

#pragma comment (lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

using namespace std;
using namespace std::chrono;

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
  mutable mutex _mtx;
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
        
    // Генеруруем ключ "на месте".
    vector<BYTE> rgbAES128Key(16);
    generate(rgbAES128Key.begin(), rgbAES128Key.end(), [n = 0]() mutable { return n += 3; });

    vKeyObject.resize(cbKeyObject);

    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(_hAESAlg, &_hKey, vKeyObject.data(), cbKeyObject, rgbAES128Key.data(), static_cast<ULONG>(rgbAES128Key.size()), 0))) {
      str << "BCryptGenerateSymmetricKey error code: " << status;
      throw runtime_error(str.str());
    }
  }
  catch (exception& ex)
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
  lock_guard<mutex> lock(_mtx);
  {
    try
    {
      NTSTATUS  status{ 0 };
      DWORD cbCipherText{ 0 };

      stringstream str;
      vector<BYTE> vResult;

      if (bEncrypt)
      {
        DWORD cbCipherText = 0;
        if (!NT_SUCCESS(status = BCryptEncrypt(_hKey, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), nullptr, nullptr, 0, nullptr, 0, &cbCipherText, BCRYPT_BLOCK_PADDING)))
        {
          str << "BCryptEncrypt 1 error code: " << status;
          throw runtime_error(str.str());
        }

        vResult.resize(cbCipherText);

        if (!NT_SUCCESS(status = BCryptEncrypt(_hKey, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), nullptr, nullptr, 0, vResult.data(), cbCipherText, &cbCipherText, BCRYPT_BLOCK_PADDING))) {
          str << "BCryptEncrypt 2 error code: " << status;
          throw runtime_error(str.str());
        }
      }
      else
      {
        if (!NT_SUCCESS(status = BCryptDecrypt(_hKey, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), nullptr, nullptr, 0, nullptr, 0, &cbCipherText, BCRYPT_BLOCK_PADDING))) {
          str << "BCryptDecrypt 1 error code: " << status;
          throw runtime_error(str.str());
        }

        vResult.resize(cbCipherText);
        if (!NT_SUCCESS(status = BCryptDecrypt(_hKey, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), nullptr, nullptr, 0, vResult.data(), cbCipherText, &cbCipherText, BCRYPT_BLOCK_PADDING))) {
          str << "BCryptDecrypt 2 error code: " << status;
          throw runtime_error(str.str());
        }
        vResult.resize(cbCipherText);
      }
      return vResult;
    }
    catch (exception& ex)
    {
      stringstream str;
      str << "CryptoProviderCNG::Crypt: [" << ex.what() << "] " << "!" << endl;
      throw runtime_error(str.str());
    }
    catch (...)
    {
      throw runtime_error("CryptoProviderCNG::Crypt: Unknown error!");
    }
  }
}

int main()
{
  try
  {    
    auto crypto_provider = make_shared<CryptoProviderCNG>();

    condition_variable cv;
    mutex m;
    int start = 0;

    function<void(int, int)> func = [crypto_provider, &m, &cv, &start](int length, int sleepms) 
    {
      this_thread::sleep_for(chrono::milliseconds(sleepms));

      unique_lock<mutex> l(m);
      cv.wait(l, [&start] {return start == 1; });
      {        
        try
        {
          cout << "length: " << length << " sleep ms: " << sleepms;

          vector<BYTE> v(length);
          generate(v.begin(), v.end(), [n = 0]() mutable { return n++; });

          bool result{ false };
          auto start = system_clock::now();
          {
            auto crypted = crypto_provider->Crypt(v);
            auto encrypted = crypto_provider->Crypt(crypted, false);            
            result = (v == encrypted);
          }
          auto end = system_clock::now();
          cout << " result: " << result << " ns: " << duration_cast<nanoseconds>(end - start).count() << endl;
        }
        catch (...) {};
      }
    };

    vector<thread> threads;
    for (int i = 0; i < 32; ++i) {
      static int length = 1024;
      threads.push_back(thread(func, length += 512, rand() % 100));
    }

    start = 1;
    cv.notify_all();

    for (auto& t : threads) {
      if (t.joinable()) {
        t.join();
      }
    }
  }
  catch (exception& ex)
  {
    cout << "Exception: " << ex.what() << endl;
  }

  return 0;
}