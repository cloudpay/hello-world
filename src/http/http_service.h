#pragma once
#ifndef __CLOUD_PAY_HTTP_SERVICE_H__
#define __CLOUD_PAY_HTTP_SERVICE_H__

#include <string>

namespace CloudPay {

	class HttpService{
	public:
		HttpService() { _errcode = -9999; _errmsg = "not set errcode"; }
		~HttpService() {}

		static int Init();

		static int Fini();

		bool Post(const std::string &url, const std::string &request, std::string *reponse, const bool verify_peer = true);
		int ErrCode() const { return _errcode; }
		const char* ErrMsg() const { return _errmsg.c_str(); }

	private:
		static size_t RecvData(char *ptr, size_t size, size_t nmemb, void *parm);
		void   SetCurlError(int errcode);

	private:
		int         _errcode;
		std::string _errmsg;
		std::string _data;

		static bool _inited;
	};

} //namespace CloudPay

#endif //__CLOUD_PAY_HTTP_SERVICE_H__