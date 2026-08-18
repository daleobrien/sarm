// Unit tests for p256_fe_mul's unrolled 4x4 product
//
// GENERATED FILE -- do not edit by hand. Regenerate with:
//   python3 scripts/p256_fe_mul_derivation.py gen-test > tests/unit/test_p256/mul_carry.c
//
// tests/unit/test_p256/mul.c already covers p256_fe_mul on
// ordinary values. This file exists for the *carry chain*: when
// p256_fe_mul stopped calling p256_bn_mul's generic loop and
// grew its own unrolled product, the risk moved from the
// algorithm (unchanged -- schoolbook) to the hand-written carry
// propagation, so the vectors here are chosen to drive that:
// operands that maximise every row's carry-out, operands whose
// product occupies only the high or only the low limbs, and
// inputs at and above the modulus.
//
// Expected values come from Python's arbitrary-precision
// integers ((a*b) % p), which share no limb-splitting or carry
// logic with the assembly under test. The generator additionally
// cross-checks itself against `cryptography` (OpenSSL) by
// computing whole public keys through the modelled carry chain
// -- see python3 scripts/p256_fe_mul_derivation.py interop.
//
// Aliasing is tested explicitly: the unrolled product reads both
// operands into registers before it writes anything, so out may
// alias a, b, or both -- p256_point_add_affine and p256_fe_inv
// both rely on that (`p256_fe_sqr(x, x)`).

#include "test_harness.h"

extern void p256_fe_mul(uint64_t out[4], const uint64_t a[4],
                        const uint64_t b[4])
    __asm__("p256_fe_mul");
extern void p256_fe_sqr(uint64_t out[4], const uint64_t a[4])
    __asm__("p256_fe_sqr");

struct mulvec { uint64_t a[4], b[4], prod[4]; const char *why; };

static const struct mulvec VECS[] = {
    { {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0x0000000000000002ULL, 0xfffffffdffffffffULL, 0xfffffffffffffffeULL, 0x00000002ffffffffULL},
      "all-ones squared: every row carry maximal" },
    { {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x0000000000000000ULL, 0xffffffff00000000ULL, 0xffffffffffffffffULL, 0x00000000fffffffeULL},
      "all-ones x 1: row 0 only, t[4] = 0" },
    { {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0x0000000000000000ULL, 0xffffffff00000000ULL, 0xffffffffffffffffULL, 0x00000000fffffffeULL},
      "1 x all-ones: one limb product per row" },
    { {0xfffffffffffffffeULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0xfffffffffffffffeULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      "(p-1)^2: the largest canonical field element" },
    { {0xfffffffffffffffeULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000002ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0xfffffffffffffffdULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      "(p-1)*2: reduction must fire" },
    { {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      "0 x all-ones: whole product zero" },
    { {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      "all-ones x 0: aliasing of the zero case" },
    { {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x8000000000000000ULL},
      {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x8000000000000000ULL},
      {0xc000000000000000ULL, 0xbfffffffbfffffffULL, 0x3fffffffffffffffULL, 0xc000000080000000ULL},
      "2^255 squared: single high bit into t[7]" },
    { {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0xffffffffffffffffULL},
      {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0xffffffffffffffffULL},
      {0x0000000100000004ULL, 0xfffffffe00000001ULL, 0xfffffffbfffffffeULL, 0x00000003fffffff7ULL},
      "top limbs only: product lives in t[6..7]" },
    { {0xffffffffffffffffULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0xffffffffffffffffULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x0000000000000001ULL, 0xfffffffffffffffeULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      "low limbs only: product lives in t[0..1]" },
    { {0xffffffffffffffffULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0xffffffffffffffffULL},
      {0xffffffffffffffffULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0xffffffffffffffffULL},
      {0x0000000300000000ULL, 0x0000000300000001ULL, 0xfffffff9fffffffeULL, 0xfffffffcfffffffeULL},
      "sparse limbs, both ends" },
    { {0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      "p x p: input at the modulus, not below it" },
    { {0x0000000000000000ULL, 0x0000000100000000ULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000000ULL, 0x0000000100000000ULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      "(p+1)^2: input above the modulus" },
    { {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000001ULL},
      {0x0000000000000000ULL, 0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x0000000000000001ULL, 0xffffffff00000000ULL, 0xffffffffffffffffULL, 0x00000000fffffffeULL},
      "pure limb shift: t[4] set with no carry in" },
    { {0xaaaaaaaaaaaaaaaaULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x5555555555555555ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x1c71c71c71c71c72ULL, 0x38e38e38e38e38e3ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      "alternating bit patterns" },
    { {0xbf46cf44542cbae4ULL, 0x26ed8eb555b6c5c3ULL, 0x14abe6f501bd4effULL, 0x8fd58dfd46af4156ULL},
      {0x3cb21b36e6adfee2ULL, 0xe2c8de2677bfc44dULL, 0x00420a92c5087130ULL, 0xc964f7a3e2f47db8ULL},
      {0xfc704bd8582faa5bULL, 0x6540ccc0a2c2867fULL, 0x24303b9391b3daa6ULL, 0x0da40abf9e2e7006ULL},
      "random" },
    { {0x2b607b6644c943f3ULL, 0x85c3c753e13eb823ULL, 0xe73dd8a09b15d827ULL, 0x0bc8b86d6e56bbcdULL},
      {0x1654264ef44e97e3ULL, 0x80d2ec4fae3b95e9ULL, 0x19a8dfd1ce1a7709ULL, 0x1ffa8c56d061f884ULL},
      {0x7e82f4a13952a15aULL, 0xac8f0f0ebf351848ULL, 0x4ecb99858926e1d4ULL, 0x95557882acedd237ULL},
      "random" },
    { {0x375b6c2b470fef79ULL, 0x6f129e6deb59a972ULL, 0xf0d56b9ce23ad562ULL, 0xa0cc45069a13e2e7ULL},
      {0x8c1ba4e35209fb95ULL, 0x9040f980c7fc2190ULL, 0xb3cff1ebf2a87674ULL, 0xbb7fd5efbca18c1aULL},
      {0x7752b1e83f3912fcULL, 0x974553c999c66d13ULL, 0x916842cc7bcdccc1ULL, 0x7fbd1c6af454607aULL},
      "random" },
    { {0xfbed67c1136e8688ULL, 0x2a2eb407fae43e90ULL, 0xa62fd1e5d295eeadULL, 0x09744c63ba1869d6ULL},
      {0x695d98f9d850f99bULL, 0x6744f0b00847340eULL, 0x2c8178e73f716445ULL, 0x65b77fb94405d8a1ULL},
      {0x3f85f49c24fd052dULL, 0xa6e1524e8548ef48ULL, 0xca2156ad570ac1edULL, 0xf82b65a38fe5ca9dULL},
      "random" },
    { {0xb1d599f0354eb5c1ULL, 0x467bd146c7708dd0ULL, 0xbdd57e0a1cb84e27ULL, 0xc80190d99a594809ULL},
      {0xc0167d05e5af3296ULL, 0x314d1dc2fb7545e9ULL, 0x787175eec61fde6fULL, 0xaf605a1d204b3384ULL},
      {0x918c13d27f31d270ULL, 0xe999543dc773d3a8ULL, 0x282e5cb0dc87cd68ULL, 0xffb6ca908784428fULL},
      "random" },
    { {0xa7e25b4b951b1386ULL, 0xb24a2be31b9149eeULL, 0x50dfbde6110ce95cULL, 0xed38b568197161f0ULL},
      {0x16c9fcac75caf3b1ULL, 0xdae0e2ab1f8ac91cULL, 0x6d26d652ffb811acULL, 0xaca0443e67005f1bULL},
      {0x2ba328ada4a2356cULL, 0x3b97bef843e7dddfULL, 0xf3b57684ddd80270ULL, 0x5e98196c2b41f735ULL},
      "random" },
    { {0x1e6bce05858ce518ULL, 0x2557f446632c6938ULL, 0xdd24511c5ec83fa6ULL, 0x4c8757b9419f8612ULL},
      {0xe82464f9e5b9a82dULL, 0x69223c8467c946a1ULL, 0x42c501b447648e76ULL, 0x20008da8e8633b42ULL},
      {0xd3dfc45b83f007a4ULL, 0xd4b598ed021b5d39ULL, 0x6806d6e2b2cf771dULL, 0x68ca03b5113b7b26ULL},
      "random" },
    { {0x8ea333b7a54cbc3cULL, 0xd208fda1142b89e3ULL, 0x3b511dd48f9a12c3ULL, 0x04c957c697df516eULL},
      {0x8a59e01fa0ee1679ULL, 0x87c4014ba15af6abULL, 0xa3599ed56f15e027ULL, 0x4507191f50f6fab7ULL},
      {0x6f3aab7f98bfe392ULL, 0x807c0785a6f58d51ULL, 0xce5c31c4fe652aa0ULL, 0xecbd43412b0df1a6ULL},
      "random" },
    { {0x958523f3fc38e6c9ULL, 0x13766c9a05318cb8ULL, 0xf76d69c033136740ULL, 0x95c4dc46e8e853a2ULL},
      {0x913ea7ab2cca7f9fULL, 0xae5799aebac9793dULL, 0xd62e6f43d51f76e8ULL, 0x15d800756b2eb7f5ULL},
      {0x68db3e07d1270d2bULL, 0xea0c598159646cb4ULL, 0xbaffa5e777759134ULL, 0x1ccef82a7f4ba9e0ULL},
      "random" },
    { {0x27beaad704c84478ULL, 0xaa0854c7b848841eULL, 0xed5f48336e787ae0ULL, 0x1a60591086bc198dULL},
      {0xb8918aa6313293bcULL, 0x08b247db6dcced7cULL, 0xe283a9769621c2f7ULL, 0xdea8c7651087501cULL},
      {0x00903f14e8dc3b24ULL, 0x4eb759b7b6c65eb5ULL, 0x92b0eae71a042c89ULL, 0x8b1152bc2d2c918aULL},
      "random" },
    { {0xf2417f4ecdd5e628ULL, 0x9cdb8fb8ee734dffULL, 0x4925e8599e17c92dULL, 0x008e41ba14e3aeaeULL},
      {0xd84cecba54a10cc7ULL, 0x79f444d5c5c39d04ULL, 0x15954c16554906abULL, 0xa2660ef638d45364ULL},
      {0xb050e78ceadfb8b7ULL, 0x85a57da08de325f5ULL, 0x39173cdae4c4f3aeULL, 0xcc76f1e8fa3f60d8ULL},
      "random" },
    { {0x00b021d5431b4d29ULL, 0xd93f346a54865231ULL, 0x40ddd45d7df4b72aULL, 0x0a535d84349b6d68ULL},
      {0x1ffe3b97895161bfULL, 0xeaf32db497ba6f1fULL, 0x6f2c36011ccc91d7ULL, 0x6a5db71967d506bdULL},
      {0x9e1b2593e44f3233ULL, 0xf35129dec854a59cULL, 0x7006a4a269771e3fULL, 0x203137443ab61e8aULL},
      "random" },
    { {0xc10d76b988e35a94ULL, 0xa6079bf434c648d4ULL, 0x2c0c5d586928bccdULL, 0xbba94bd0c339f184ULL},
      {0x8560ad9df4debf2dULL, 0xc57f86f21a87a093ULL, 0x0e1d99852d47835cULL, 0x8ab9783348372283ULL},
      {0x5a8f90b6bba1cf83ULL, 0x86ef5d121ddaace9ULL, 0x48cdc4ca185042c8ULL, 0x7613aba0647d5663ULL},
      "random" },
    { {0x43ac3b709314dd6aULL, 0xabc09884667302f0ULL, 0x4b0a52c988bffaadULL, 0x7c9661b3a2354c7dULL},
      {0xfc780008776d50b1ULL, 0x41e75db82a534827ULL, 0xe94cd845da885414ULL, 0x6a2de312abb2edb9ULL},
      {0xb11efaadd5639a7bULL, 0x4a610f0743e57c68ULL, 0x579e1f9f202affecULL, 0x15b7d05116a16371ULL},
      "random" },
    { {0xb37d2bd2e1989c92ULL, 0x14e72fdc6cd5c60aULL, 0x5bb3aa1aabc5f581ULL, 0x390c823386a8ccb2ULL},
      {0xb197e0977e6e8da2ULL, 0xd5aad588008e8d01ULL, 0x73d6a5d05e886718ULL, 0xe0612126ef1cde8cULL},
      {0xc3a49a3db49c6a5dULL, 0x28976df1c5e98755ULL, 0x8046437b597d141cULL, 0xa7f8efed7015aa18ULL},
      "random" },
    { {0x6408061ddee85319ULL, 0x396869f8648669c2ULL, 0xaf428ba778bedac2ULL, 0x197ec4f909a8ec3dULL},
      {0x98fe225a6fd4beaeULL, 0xeda3acee19b18ff5ULL, 0xb8efe96e98eb2ca0ULL, 0x106e0412a02c3f11ULL},
      {0x13266cfa3e7b68e4ULL, 0xa1cb34dd1e6cf4ecULL, 0xe4c26ceb8194fb44ULL, 0xac800dc9434e6696ULL},
      "random" },
    { {0xdf4e68b02ab7adb1ULL, 0x6e7a8d819b00dbabULL, 0x44d422b069ebb245ULL, 0xe20dd9299758ee3aULL},
      {0x6f5c0cd9fb186c29ULL, 0xd47586b2f8ed26e2ULL, 0x3b4cb0a40ad60eb5ULL, 0xe08bc640905f6869ULL},
      {0xd3bc20b57934c2fcULL, 0x89ca8827010da23aULL, 0x910b87ed690f3ef2ULL, 0x9bc602e9718706bfULL},
      "random" },
    { {0x7c4a9c5a8280114cULL, 0x2935691bf2a7c2beULL, 0x475b34d0eee5a1c6ULL, 0xf7a167175e7d0182ULL},
      {0x6056569ac830f982ULL, 0x7a6735b6f4b09210ULL, 0xed21b6c7ca442f28ULL, 0x29fe5a58692446ddULL},
      {0x3e65a5f5763bb9fcULL, 0xf98adf902465482cULL, 0x6e0e93348d30ac99ULL, 0x1db212667cd70f2aULL},
      "random" },
    { {0x458ab949291412aeULL, 0x72d0d186b0598581ULL, 0x743d3ab02742ceb1ULL, 0x83bcd349c7ea3281ULL},
      {0x15cb403004569457ULL, 0x9e906fd33b0a30c3ULL, 0x4f6ef7e429dbcbc2ULL, 0x5348b20111f09e42ULL},
      {0xd2ae617a23fc5dbbULL, 0x717a192796549271ULL, 0x8260bb2446933a70ULL, 0xa31ffb06fb2e6cdcULL},
      "random" },
    { {0x6b38b0d59986ae75ULL, 0x6971649853df8131ULL, 0xe3c151555a4d54c9ULL, 0xf26a20af85773e2eULL},
      {0x3d493407eedb4cbcULL, 0xc56dc0c8448f1a2aULL, 0xef946c43a134be17ULL, 0xf9144960958f473eULL},
      {0xe279e500ddef69d8ULL, 0xab55cc4ecad4c407ULL, 0x6202fc891990ff9eULL, 0x251b9d2ae7015ec1ULL},
      "random" },
    { {0xd66736fe5a481377ULL, 0x7c9131f2e55a778aULL, 0x02b318054dd59666ULL, 0x6aa4ad76ac6f0152ULL},
      {0xa346044118ecf1a2ULL, 0xbae46254a1c6fddbULL, 0x8f580815fe8ae9b4ULL, 0xf47fb6e709e883baULL},
      {0x69d6bc1b714f902bULL, 0x20048d9da9072e65ULL, 0x129999860141576bULL, 0x23953df3c2bc94b6ULL},
      "random" },
    { {0x8fb3d260bad3a163ULL, 0x3e0946448f762aa9ULL, 0x2a56f41cd14eb66aULL, 0xab1c434e979bbe52ULL},
      {0x3c88784b4a085bdeULL, 0x5f9968dd8981bdaeULL, 0x14b7fc0e57236870ULL, 0xc4179410980dd94dULL},
      {0x5a33e179a2fb48e3ULL, 0x2d2a5123ef0e4322ULL, 0x1be58ae4c665b7adULL, 0x01dd5724c2b7ceabULL},
      "random" },
    { {0xcaa22fac3f77aa08ULL, 0x27d52c681aa735e1ULL, 0xbe1b582d64adcc65ULL, 0x22cdaa23ce3a37dbULL},
      {0xe1e76c91af7aac6fULL, 0x79016f665221072aULL, 0x2cb538f064f4e54cULL, 0xf87d425b08bb18eaULL},
      {0x61b1e2efdc876246ULL, 0x3b4777c3abff57eaULL, 0x6e060aef0deb7327ULL, 0x9241f8be8e38810cULL},
      "random" },
    { {0x24b2b2e9c5d42aacULL, 0x3dbffc8d1ef7c7e6ULL, 0x20d56bd4fadcd95aULL, 0xca102e57a1d2e3a2ULL},
      {0x9ab55592f66b99fdULL, 0x0581145e345a70f4ULL, 0xf1ea1a988fce33a5ULL, 0xd908084379d9364fULL},
      {0xec63fec67c3431fdULL, 0x203ac555c31b4e34ULL, 0xa1476095c9d24ce2ULL, 0x09367967c4a2b26dULL},
      "random" },
    { {0xb8723dcd8a0ba1bcULL, 0x5f4ab92c8a66fceaULL, 0xd3575d3664c02f08ULL, 0xe6dd5343b8b9c6f1ULL},
      {0x5d439ee788e667f4ULL, 0x8276b0ad22b35468ULL, 0x368299d9509ae411ULL, 0x5120d88c6c1c876fULL},
      {0x14dcf687568d77acULL, 0xeca05b536f234a73ULL, 0xa07e54559a8c4425ULL, 0x7f39647b2206f906ULL},
      "random" },
    { {0x49fcc2eaea2e9fe9ULL, 0x87b1d1f56bc9a578ULL, 0x8d1d20c7e5b2de6eULL, 0xbb127c44841f8645ULL},
      {0x1bf681b149527095ULL, 0x32f997d6101c991fULL, 0x580d93498e0aceb9ULL, 0x2c7bf8df9e4df5ccULL},
      {0x8a8f941ee7750830ULL, 0x51bb977a45e8af78ULL, 0x359b0057ae91122fULL, 0x29d8d026d9b0d88fULL},
      "random" },
    { {0x206a6a893abe5f46ULL, 0xea6b9913c06348edULL, 0x5c1db01479ea2b91ULL, 0x7a0faeb89ed0463aULL},
      {0xdbed55b393113a46ULL, 0x5e23fa1c2da265e2ULL, 0xb4d8894fd00753d2ULL, 0x6308ea7da84b1617ULL},
      {0x91dad38b9e9aa7cdULL, 0x400fbe078c3c5b61ULL, 0x5a53d5b860a201d2ULL, 0x87139c7d7a7f64ceULL},
      "random" },
    { {0x21adb64dbec9aee8ULL, 0x45532350cb18f603ULL, 0x90bd6a986bc29387ULL, 0x5092ca563fcecbf0ULL},
      {0x46225f22b10c8da3ULL, 0x03d222905d035a74ULL, 0x5702f6684f85e5bcULL, 0x774e80bfb50fc3d7ULL},
      {0xe1d381f1a0317b6fULL, 0xad7ed9576ecbef6fULL, 0x69f519abef7ed3bcULL, 0x9efcac39ebe244d9ULL},
      "random" },
    { {0x05c24a7417440c4bULL, 0x7ecdbcb504c7d783ULL, 0xe5b866db7a7002a3ULL, 0x9284f1c397a28704ULL},
      {0x560184b382780799ULL, 0x5ba35debdefa3b05ULL, 0x4719fdf2cc5a3f89ULL, 0xcf624ae23667bf3bULL},
      {0x4388a813bd25761eULL, 0xfa50e08fe180a7caULL, 0x7c934b543037ea57ULL, 0x699039cc5767f114ULL},
      "random" },
    { {0x4522df5dfb80fefcULL, 0xf3c17803da1f257dULL, 0x29e3e3590ac90358ULL, 0xeaac4b80dd473166ULL},
      {0x3e9b9bdb10d0e84bULL, 0x6bdb4e2770685926ULL, 0x7aeb7fd0a4734220ULL, 0x01c7d67d2527228aULL},
      {0x9d1db9340e67147eULL, 0xb042fcb1b3b7692dULL, 0x8cff977868b7cc67ULL, 0xe946ef9a2c1b818bULL},
      "random" },
};
#define NVECS ((int)(sizeof VECS / sizeof VECS[0]))

// p256_fe_sqr is a trampoline into p256_fe_mul (it sets b = a
// and falls through), so it shares the product entirely. These
// pin that down rather than assuming it.
static const struct { uint64_t a[4], sq[4]; } SQRS[] = {
    { {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0x0000000000000002ULL, 0xfffffffdffffffffULL, 0xfffffffffffffffeULL, 0x00000002ffffffffULL} },
    { {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0x0000000000000002ULL, 0xfffffffdffffffffULL, 0xfffffffffffffffeULL, 0x00000002ffffffffULL} },
    { {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL} },
    { {0xfffffffffffffffeULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL} },
    { {0xfffffffffffffffeULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL} },
    { {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL} },
    { {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
      {0x0000000000000002ULL, 0xfffffffdffffffffULL, 0xfffffffffffffffeULL, 0x00000002ffffffffULL} },
    { {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x8000000000000000ULL},
      {0xc000000000000000ULL, 0xbfffffffbfffffffULL, 0x3fffffffffffffffULL, 0xc000000080000000ULL} },
    { {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0xffffffffffffffffULL},
      {0x0000000100000004ULL, 0xfffffffe00000001ULL, 0xfffffffbfffffffeULL, 0x00000003fffffff7ULL} },
    { {0xffffffffffffffffULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x0000000000000001ULL, 0xfffffffffffffffeULL, 0x0000000000000000ULL, 0x0000000000000000ULL} },
    { {0xffffffffffffffffULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0xffffffffffffffffULL},
      {0x0000000300000000ULL, 0x0000000300000001ULL, 0xfffffff9fffffffeULL, 0xfffffffcfffffffeULL} },
    { {0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL} },
    { {0x0000000000000000ULL, 0x0000000100000000ULL, 0x0000000000000000ULL, 0xffffffff00000001ULL},
      {0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL} },
    { {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000001ULL},
      {0xfffffffefffffffeULL, 0x00000002ffffffffULL, 0x0000000000000002ULL, 0xfffffffe00000001ULL} },
    { {0xaaaaaaaaaaaaaaaaULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
      {0x38e38e38e38e38e4ULL, 0x71c71c71c71c71c6ULL, 0x0000000000000000ULL, 0x0000000000000000ULL} },
    { {0xbf46cf44542cbae4ULL, 0x26ed8eb555b6c5c3ULL, 0x14abe6f501bd4effULL, 0x8fd58dfd46af4156ULL},
      {0xecf07a9ab29526f7ULL, 0x64f69c172dd04449ULL, 0x39124b515db25c0cULL, 0x7035033eb811681fULL} },
    { {0x2b607b6644c943f3ULL, 0x85c3c753e13eb823ULL, 0xe73dd8a09b15d827ULL, 0x0bc8b86d6e56bbcdULL},
      {0xb9c7932245d827b9ULL, 0x992870793cb17fc4ULL, 0x34dd7904cd85584dULL, 0x4dc2997119f0d032ULL} },
    { {0x375b6c2b470fef79ULL, 0x6f129e6deb59a972ULL, 0xf0d56b9ce23ad562ULL, 0xa0cc45069a13e2e7ULL},
      {0xfc8e69df536c91f2ULL, 0x7bd3d4ed601c8093ULL, 0x89c9e2c7583b26dcULL, 0xa3ce323093bd17f1ULL} },
    { {0xfbed67c1136e8688ULL, 0x2a2eb407fae43e90ULL, 0xa62fd1e5d295eeadULL, 0x09744c63ba1869d6ULL},
      {0xe7fa5656f6310c68ULL, 0xf4e1a0c8bbf7df52ULL, 0x45c7be3cc359a60fULL, 0xf963502a334e717cULL} },
    { {0xb1d599f0354eb5c1ULL, 0x467bd146c7708dd0ULL, 0xbdd57e0a1cb84e27ULL, 0xc80190d99a594809ULL},
      {0x8aff2daa6ccad4ccULL, 0xf083ceebcaab4f42ULL, 0x23aa9fb30e15b88eULL, 0xd4f4e8bb593ae19bULL} },
};
#define NSQRS ((int)(sizeof SQRS / sizeof SQRS[0]))

static void test_fe_mul_carry(void) {
    TEST_SUITE("p256_fe_mul carry chain");

    for (int i = 0; i < NVECS; i++) {
        uint64_t out[4], t[4];
        p256_fe_mul(out, VECS[i].a, VECS[i].b);
        ASSERT_EQ(VECS[i].why, 0, memcmp(out, VECS[i].prod, 32));

        // out aliases a: the product reads both operands into
        // registers before writing anything.
        memcpy(t, VECS[i].a, 32);
        p256_fe_mul(t, t, VECS[i].b);
        ASSERT_EQ("out == a", 0, memcmp(t, VECS[i].prod, 32));

        // out aliases b
        memcpy(t, VECS[i].b, 32);
        p256_fe_mul(t, VECS[i].a, t);
        ASSERT_EQ("out == b", 0, memcmp(t, VECS[i].prod, 32));
    }

    for (int i = 0; i < NSQRS; i++) {
        uint64_t out[4], t[4];
        p256_fe_sqr(out, SQRS[i].a);
        ASSERT_EQ("p256_fe_sqr", 0, memcmp(out, SQRS[i].sq, 32));

        // squaring in place -- p256_fe_inv does exactly this
        memcpy(t, SQRS[i].a, 32);
        p256_fe_sqr(t, t);
        ASSERT_EQ("p256_fe_sqr in place", 0,
                  memcmp(t, SQRS[i].sq, 32));

        // out == a == b through p256_fe_mul itself
        memcpy(t, SQRS[i].a, 32);
        p256_fe_mul(t, t, t);
        ASSERT_EQ("out == a == b", 0, memcmp(t, SQRS[i].sq, 32));
    }
}

int main(void) {
    test_fe_mul_carry();
    test_summary();
    return 0;
}
