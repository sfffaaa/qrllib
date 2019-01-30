// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <xmss-alt/algsxmss.h>
#include <xmssBasic.h>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>
#include <qrl/qrlHelper.h>

namespace {
#define XMSS_HEIGHT 4

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

TEST(XmssBasic_Default, JsonPlaintextTest)
{
    std::vector<unsigned char> seed;
    for (unsigned char i = 0; i<48; i++)
        seed.push_back(i);

    //generate
    XmssBasic xmss(seed, XMSS_HEIGHT, eHashFunction::SHAKE_128, eAddrFormatType::SHA256_2X);
    auto pk = xmss.getPK();
    //finish generate

    std::string message = TEST_JSON_PLAINTEXT;
    std::vector<unsigned char> data_ref(message.begin(), message.end());
    std::vector<unsigned char> data(message.begin(), message.end());

    //sign
    auto signature = xmss.sign(data);
    //finish signed


    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "data       :" << data.size() << " bytes\n" << bin2hstr(data, 64) << std::endl;
    std::cout << "signature  :" << signature.size() << " bytes\n" << bin2hstr(signature, 64) << std::endl;

    // verify
    bool valid = XmssBasic::verify(data, signature, pk);
    // finish verify

    EXPECT_TRUE(valid);
    EXPECT_EQ(data, data_ref);

    auto sk = xmss.getSK();
    std::cout << std::endl;
    std::cout << "seed:" << seed.size() << " bytes\n" << bin2hstr(seed, 32) << std::endl;
    std::cout << "pk  :" << pk.size() << " bytes\n" << bin2hstr(pk, 32) << std::endl;
    std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 32) << std::endl;
}

}
