#include "gmock/gmock.h"
#include "key.h"
#include "pubkey.h"
#include "util.h"

#include "librustzcash.h"
#include <sodium.h>

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

struct ECCryptoClosure
{
    ECCVerifyHandle handle;
};

ECCryptoClosure instance_of_eccryptoclosure;

int main(int argc, char **argv) {
  assert(sodium_init() != -1);
  ECC_Start();

  fs::path sapling_spend = ZC_GetParamsDir() / "sapling-spend.params";
  fs::path sapling_output = ZC_GetParamsDir() / "sapling-output.params";
  fs::path sprout_groth16 = ZC_GetParamsDir() / "sprout-groth16.params";

    static_assert(
        sizeof(fs::path::value_type) == sizeof(codeunit),
        "librustzcash not configured correctly");
    auto sapling_spend_str = sapling_spend.native();
    auto sapling_output_str = sapling_output.native();
    auto sprout_groth16_str = sprout_groth16.native();

    librustzcash_init_zksnark_params(
        reinterpret_cast<const codeunit*>(sapling_spend_str.c_str()),
        sapling_spend_str.length(),
        reinterpret_cast<const codeunit*>(sapling_output_str.c_str()),
        sapling_output_str.length(),
        reinterpret_cast<const codeunit*>(sprout_groth16_str.c_str()),
        sprout_groth16_str.length()
    );

  testing::InitGoogleMock(&argc, argv);

  // The "threadsafe" style is necessary for correct operation of death/exit
  // tests on macOS (https://github.com/zcash/zcash/issues/4802).
  testing::FLAGS_gtest_death_test_style = "threadsafe";

  auto ret = RUN_ALL_TESTS();

  ECC_Stop();
  return ret;
}
