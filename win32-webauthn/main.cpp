#include <iostream>
#include <vector>
#include <string>
#include <sodium.h>					 // Libsodium buat Base64
#include <nlohmann/json.hpp> // JSON library

using json = nlohmann::json;

int main()
{
	// 1. Inisialisasi Libsodium
	if (sodium_init() < 0)
		return 1;

	// 2. Simulasi data BINARY (Misal: Public Key atau Signature)
	unsigned char raw_data[32];
	randombytes_buf(raw_data, sizeof raw_data); // Isi data acak

	// 3. ENCODE: Binary -> Base64 (Text)
	// Libsodium punya fungsi sodium_bin2base64 yang aman dan kencang
	char b64_output[64];
	sodium_bin2base64(b64_output, sizeof b64_output, raw_data, sizeof raw_data,
										sodium_base64_VARIANT_ORIGINAL);

	std::cout << "--- DATA ASLI (HEX) ---" << std::endl;
	// (Cuma buat liat isi aslinya)

	// 4. MASUKIN KE JSON
	json webauthn_packet;
	webauthn_packet["username"] = "Renol_Cyber";
	webauthn_packet["challenge_b64"] = b64_output; // Base64 masuk sini
	webauthn_packet["algorithm"] = "ED25519";

	// Serialize JSON ke String buat dikirim/disimpan
	std::string json_result = webauthn_packet.dump(4); // indent 4 biar cantik
	std::cout << "\n--- HASIL JSON ---" << std::endl;
	std::cout << json_result << std::endl;

	// 5. DECODE: Base64 (Text) -> Binary kembali
	// Misalnya kita nerima JSON dan mau ambil datanya lagi
	std::string b64_input = webauthn_packet["challenge_b64"];
	unsigned char decoded_bin[32];
	size_t bin_len;

	sodium_base642bin(decoded_bin, sizeof decoded_bin,
										b64_input.c_str(), b64_input.length(),
										nullptr, &bin_len, nullptr,
										sodium_base64_VARIANT_ORIGINAL);

	std::cout << "\n--- DECODE BERHASIL ---" << std::endl;
	std::cout << "Data kembali ke ukuran: " << bin_len << " bytes" << std::endl;

	return 0;
}