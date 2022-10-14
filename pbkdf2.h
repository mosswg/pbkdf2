#include <vector>
#include <string>
#include <cstdint>
#include <cmath>
#include "SHA1_HMAC/SHA1_HMAC.h"

namespace mosswg {
	std::string convert_be(uint32_t* data, uint32_t data_size) {
		std::string out;

		for (int i = 0; i < data_size / 4; i++) {
			out += ((data[i] & 0xFF000000) >> 24);
			out += ((data[i] & 0xFF0000) >> 16);
			out += ((data[i] & 0xFF00) >> 8);
			out += (data[i] & 0xFF);
		}

		return out;
	}

	uint32_t* pbkdf2_xor(uint32_t* a, const uint32_t* b) {
		a[0] ^= b[0];
		a[1] ^= b[1];
		a[2] ^= b[2];
		a[3] ^= b[3];
		a[4] ^= b[4];

		return a;
	}

	/// Source: https://en.wikipedia.org/wiki/PBKDF2#Key_derivation_process
	std::string pbkdf2(const std::string& password, std::string salt, int iterations, int length) {

		std::string dk;

		std::vector<uint32_t*> T;

		for (int i = 1; i <= ceil(length/20.0); i++) {




			std::vector<uint32_t*> U;
			U.push_back(new uint32_t[5]);

			salt.push_back((i >> 24) & 0xff);
			salt.push_back((i >> 16) & 0xff);
			salt.push_back((i >> 8) & 0xff);
			salt.push_back(i & 0xff);

			hmac(password, salt, U[0]);



			for (int c = 2; c <= iterations; c++) {
				U.push_back(new uint32_t[5]);
				hmac(password, U[i-1], 20, U[i]);
				pbkdf2_xor(U[0], U[1]);
			}

			dk += convert_be(U[0], 20);

			for (auto& j : U) {
				delete[] j;
			}
		}

		return dk.substr(0, length);
	}

}
