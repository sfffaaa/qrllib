// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <xmssFast.h>
#include <iostream>
#include "gtest/gtest.h"
#include <qrl/misc.h>
#include <mytest_lib/cpucycles.h>
#include <mytest_lib/speed.h>

namespace {
#define XMSS_HEIGHT 4
#define NTESTS 50

#define TEST_JSON_PLAINTEXT "{\n" \
"		body: {\n" \
"				\"from\": \"pub_key_generated_by_library_in_testing_1\",\n" \
"				\"to\": \"pub_key_generated_by_library_in_testing_2\",\n" \
"				\"amount\": 3,1415,\n" \
"				\"itemHash\": \"bdad5ccb7a52387f5693eaef54aeee6de73a6ada7acda6d93a665abbdf954094\"\n" \
"				\"seed\": \"2953135335240383704\"\n" \
"		},\n" \
"		\"fee\": 0,7182,\n" \
"		\"network_id\": 7,\n" \
"		\"protocol_version\": 0,\n" \
"		\"service_id\": 5,\n" \
"}"

unsigned long long timing_overhead;

TEST(XmssFastSHA2_test, JsonPlaintextTest)
{
	std::string message = TEST_JSON_PLAINTEXT;
	std::vector<unsigned char> data_ref(message.begin(), message.end());
	std::vector<unsigned char> data(message.begin(), message.end());

	for (unsigned int i = 0; i < NTESTS; i++) {
		std::vector<unsigned char> seed = getRandomSeed(48, std::string(""));

		//generate
        XmssFast xmss(seed, XMSS_HEIGHT, eHashFunction::SHA2_256, eAddrFormatType::SHA256_2X);
		auto pk = xmss.getPK();
		//finish generate

		//sign
		auto signature = xmss.sign(data);
		//finish signed

		// verify
		bool valid = XmssFast::verify(data, signature, pk);
		// finish verify

		EXPECT_TRUE(valid);
		EXPECT_EQ(data, data_ref);
	}
}

TEST(XmssFastSHA2_test, JsonPlaintextRun)
{
	std::string message = TEST_JSON_PLAINTEXT;
	std::vector<unsigned char> data_ref(message.begin(), message.end());
	std::vector<unsigned char> data(message.begin(), message.end());
	unsigned long long tkeygen[NTESTS], tsign[NTESTS], tverify[NTESTS];
	unsigned long long totalLength = 0;
	timing_overhead = cpucycles_overhead();

	for (unsigned int i = 0; i < NTESTS; i++) {
		std::vector<unsigned char> seed = getRandomSeed(48, std::string(""));

		//generate
		tkeygen[i] = cpucycles_start();
        XmssFast xmss(seed, XMSS_HEIGHT, eHashFunction::SHA2_256, eAddrFormatType::SHA256_2X);
		auto pk = xmss.getPK();
		tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;
		//finish generate

		//sign
		tsign[i] = cpucycles_start();
		auto signature = xmss.sign(data);
		tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;
		//finish signed

		// verify
		tverify[i] = cpucycles_start();
		bool valid = XmssFast::verify(data, signature, pk);
		tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;
		// finish verify

		EXPECT_TRUE(valid);
		EXPECT_EQ(data, data_ref);
		totalLength += signature.size();
	}
	print_results("keygen:", tkeygen, NTESTS);
	print_results("sign: ", tsign, NTESTS);
	print_results("verify: ", tverify, NTESTS);
	printf("average length: %llu\n", (totalLength / NTESTS));
}

}
