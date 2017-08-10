#include "stdafx.h"
#include "http_service.h"

#include "config/configure.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <curl/curl.h>

#include <iostream>

namespace CloudPay {

	class Mutex {
	public:
		Mutex() 
		{
			_ok = false;
			_mutex = CreateMutex(NULL, FALSE, NULL);
			if (!_mutex)
				return;

			_ok = true;
		}

		~Mutex()
		{
			if (_mutex)
				CloseHandle(_mutex);
			_ok = false;
		}

		void Lock()
		{
			WaitForSingleObject(_mutex, INFINITE);
		}

		void Unlock()
		{
			ReleaseMutex(_mutex);
		}


		explicit operator bool() const
		{
			return _ok;
		}

	private:
		HANDLE _mutex;
		bool _ok;
	}; 

	static Mutex  *g_mutex = NULL;

	static void Locking(int mode, int n, const char *, int)
	{
		if ((mode & CRYPTO_LOCK)) {
			g_mutex[n].Lock();
		}
		else {
			g_mutex[n].Unlock();
		}
	}

	bool HttpService::_inited = false;

	int HttpService::Init()
	{
		if (_inited)
			return 0;

		//openssl初始化
		OpenSSL_add_all_algorithms();
		int locks = CRYPTO_num_locks();
		if (locks > 0) {
			g_mutex = new Mutex[locks];
			CRYPTO_set_locking_callback(Locking);
		}

		if (!SSL_library_init()) {
			if (g_mutex)
				delete [] g_mutex;

			return -1;
		}

		SSL_load_error_strings();

		//libcurl初始化
		curl_global_init(CURL_GLOBAL_ALL);

		_inited = true;
		return 0;
	}

	int HttpService::Fini()
	{
		if (!_inited)
			return 0;

		curl_global_cleanup();

		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_remove_thread_state(NULL);
		ERR_free_strings();

		delete[] g_mutex;
		g_mutex = NULL;

		_inited = false;
		return 0;
	}

	class DeleteCurlSList{
	public:
		DeleteCurlSList(struct curl_slist *list) :_list(list){}
		~DeleteCurlSList()
		{
			if (_list)
				curl_slist_free_all(_list);
		}
	private:
		struct curl_slist *_list;
	};

	void HttpService::SetCurlError(int errcode)
	{
		_errcode = errcode;
		_errmsg  = curl_easy_strerror(static_cast<CURLcode>(errcode));
	}

	size_t HttpService::RecvData(char *ptr, size_t size, size_t nmemb, void *parm)
	{
		size_t length = size * nmemb;
		HttpService *https = (HttpService*)parm;
		std::string &str = https->_data;

		str.append(ptr, length);

		return length;
	}

	bool HttpService::Post(const std::string &url, const std::string &request, std::string *reponse, const bool verify_peer)
	{
		CURL *curl;
		CURLcode ret;

		curl = curl_easy_init();
		if (!curl) {
			_errcode = -1;
			_errmsg = "curl_easy_init fail";
			return false;
		}
		
		int connect_timeout = 10;
		if (CloudPay::Configure::GetInstance()->GetHttpsConnectTimeout() > 0)
			connect_timeout = CloudPay::Configure::GetInstance()->GetHttpsConnectTimeout();

		ret = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);  // 链接超时
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}

		int post_timeout = 10;
		if (CloudPay::Configure::GetInstance()->GetHttpsPostTimeout() > 0)
			post_timeout = CloudPay::Configure::GetInstance()->GetHttpsPostTimeout();
		ret = curl_easy_setopt(curl, CURLOPT_TIMEOUT, post_timeout);   // 通讯超时
		if (ret) {
			SetCurlError(ret);
			return false;
		}

		bool https = false;
		if (url.find("https://") != std::string::npos) {
			https = true;
		}

		struct curl_slist *list = NULL;
		list = curl_slist_append(list, "Content-Type: application/json");
		DeleteCurlSList delete_curl_slist(list);

		ret = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
		if (ret) {
			SetCurlError(ret);
			return false;
		}
		
		ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, RecvData);
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}
		ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}

		if (https && verify_peer) {
			ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L); // 严格验证服务器的域名
			if (ret != CURLE_OK) {
				SetCurlError(ret);
				return false;
			}
			ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 验证服务器的证书
			if (ret != CURLE_OK) {
				SetCurlError(ret);
				return false;
			}

			std::string root_ca = "./cloudpayrootca.pem";
			if (!CloudPay::Configure::GetInstance()->GetRootCa().empty())
				root_ca = CloudPay::Configure::GetInstance()->GetRootCa();
			ret = curl_easy_setopt(curl, CURLOPT_CAINFO, root_ca.c_str());
			if (ret != CURLE_OK) {
				SetCurlError(ret);
				return false;
			}		
		}

		//暂时不支持安全加密的代理模式
		if (!CloudPay::Configure::GetInstance()->GetHttpsProxyUrl().empty()) {
			ret = curl_easy_setopt(curl, CURLOPT_PROXY, CloudPay::Configure::GetInstance()->GetHttpsProxyUrl().c_str());
			if (ret != CURLE_OK) {
				SetCurlError(ret);
				return false;
			}

			ret = curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, CloudPay::Configure::GetInstance()->GetHttpsProxyUserPwd().c_str());
			if (ret != CURLE_OK) {
				SetCurlError(ret);
				return false;
			}
		}

		ret = curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}
		ret = curl_easy_setopt(curl, CURLOPT_POST, 1L);
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}
		ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.c_str());
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}

		// 获取返回值
		ret = curl_easy_perform(curl);
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}

		long status = 0;
		ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}
		char *raw;
		ret = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &raw);
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}
		ret = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &raw);
		if (ret != CURLE_OK) {
			SetCurlError(ret);
			return false;
		}

		curl_easy_cleanup(curl);

		_errcode = 0;
		_errmsg = "success";

		*reponse = _data;
		return true;
	}

} //namespace CloudPay