// Copyright (c) 2021-2022, The GNTL Project
// Copyright (c) 2014-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"

using namespace epee;

#undef GNTL_DEFAULT_LOG_CATEGORY
#define GNTL_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::hex_to_pod(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }
    else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map<uint64_t, crypto::hash>::const_iterator highest = std::max_element(m_points.begin(), m_points.end(),
             (boost::bind(&std::map<uint64_t, crypto::hash>::value_type::first, boost::placeholders::_1) <
              boost::bind(&std::map<uint64_t, crypto::hash>::value_type::first, boost::placeholders::_2)));

    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    if (nettype == TESTNET)
    {
//      ADD_CHECKPOINT(0, "60077b4d5cd49a1278d448c58b6854993d127fcaedbdeab82acff7f7fd86e328");
      return true;
    }
    if (nettype == STAGENET)
    {
//      ADD_CHECKPOINT(0, "60077b4d5cd49a1278d448c58b6854993d127fcaedbdeab82acff7f7fd86e328");
      return true;
    }
        ADD_CHECKPOINT(0, "4010c82bbd835d9580dd95fdcd0834d90102782f06016c9f069a2303ddc682e0");
        ADD_CHECKPOINT(2500, "d362848551a2eaa0c0fc558264c09b9a69afe37539f46f57e975731c9325ab58");
        ADD_CHECKPOINT(5000, "ce450b174764f4cf1132d32f1df95613a2e483174c5d627e39bda844c5da0cbf");
        ADD_CHECKPOINT(7500, "64d87b76b5d9ef5a1907489c2ea76c72d296f9c861b46aadcbe96e6dea55eb26");
        ADD_CHECKPOINT(10000, "6c25524cd1cb51bdd7ca5e284f084e7edcccd2a552cb103c1f3feae8428edeab");
        ADD_CHECKPOINT(12500, "7f424a3998ffc40c0522383424768ba695928bee124f2f55a2620111f36c05ac");
        ADD_CHECKPOINT(15000, "7966167d73e99a81dac338f26c6892f121762c7ee079400c9edd2b73e751bee6");
        ADD_CHECKPOINT(17500, "747708fbeffe91d1c6261dd1139a4dc775c1f0e27f31e06226a1a9dc0392b8c3");
        ADD_CHECKPOINT(20000, "9dab170d2bf1b8832af876b610fefe0aa4e8f9e5031746c2804ecae15967e560");
        ADD_CHECKPOINT(22500, "3b7e70a0ef6d8937ab1a8a068804fb3b1f46c67f2e31e6ba18499fbd173c4e9f");
        ADD_CHECKPOINT(25000, "b0fba447e624bc46ddb558e542993f4bd72187d702b366a77633e45c83f87d55");
        ADD_CHECKPOINT(27500, "5d3c1df497912a78a621242a6baad547556eb52df41a75869d8f7d3d4c776a43");
        ADD_CHECKPOINT(30000, "c3debcd0f98abb24dfc8d98bc624fa7de05093bd716b54ea45599b88987909c9");
        ADD_CHECKPOINT(32500, "5bd3fb43ed4637f7213a4ab91196b20947b23f7c09c4b7b350f1786e62d78bd0");
        ADD_CHECKPOINT(35000, "f886de5cf5c58d373f7757d19b2941bc52278cfde597585ae18f5afdd2e7d85b");
        ADD_CHECKPOINT(37500, "8612666aca39ad750b9fb8cd19b9a0cf07f530e47655926eee236c0381f989a8");
        ADD_CHECKPOINT(40000, "455ebe7cb764770bf5e69bf4f681ef1cefdc48d98b879bde5e24276e2265b3b2");
        ADD_CHECKPOINT(42500, "4757629c1d8fce0324e4b72ec6637fdb8374fc55a30d3480c308ec66fd181875");
        ADD_CHECKPOINT(45000, "d260e92c5f0375698fd08cee47146773addabf05581a440be0716cea70c10987");
        ADD_CHECKPOINT(47500, "a9b308f6f6c48199b41102b31e5d8ea41ac4a6f11c03c15d3edc83af39fd5033");
        ADD_CHECKPOINT(50000, "645a3f1ab164395437d0a9c61feb2815623dac06f632871e716472efae886c4a");
        ADD_CHECKPOINT(52500, "bbf08012d5b492072206daafe52c05f981de25c6b61e09899b91d296ab3a2692");
        ADD_CHECKPOINT(55000, "18ff5a02e2e2f2055c71fb96ae3e2e75b531559f2b923138147a9f29f5c866f9");
        ADD_CHECKPOINT(57500, "74090f7cc94e40c75ac8fe1aa2fc9c2f19ca2884fe6f7c5cddc30c92fc62787a");
        ADD_CHECKPOINT(60000, "11faca63b82439d23dc763a9e8d5dd6edac412ba667d48a925404c9041751204");
        ADD_CHECKPOINT(62500, "c80e49ee5876f3694b7a5b72feb7282bef561df009e1a03949e900d30f754d46");
        ADD_CHECKPOINT(65000, "b01a91407a313124271b4bed299da20f74c33a315308032dd08a307c9809827e");
        ADD_CHECKPOINT(67500, "dd77a3ac500b6affb4617d4498d4e22d8ae22bd47dbca286b9c16512a96e55a4");
        ADD_CHECKPOINT(70000, "7d8d3b9692bf7de785eedc5d10e95d27d5e5afa7fd3b65e9ddc37a142b7373c3");
        ADD_CHECKPOINT(72500, "55594c8d820a7b20143124afb51983539cc897755c965636ead60dad71c6b8dd");
        ADD_CHECKPOINT(75000, "e3c1d3fb0d1d14f7424bab1b6df562a2a6fc8ee81e99f8a55a6bc9a080335afa");
        ADD_CHECKPOINT(77500, "0f338b0fee9c084c15905cc289fccbe233f8cc8af059355e647ce3a06e78d57e");
        ADD_CHECKPOINT(80000, "b709d6fd9874287ca013c7fc8560eb625d190420566c1b229e5989f8cebc375e");
        ADD_CHECKPOINT(82500, "3f0061fdfd220e767a66695742b1d6b926a6aa1dbc1a046ca935efee2ff3af7d");
        ADD_CHECKPOINT(85000, "79f5971c841a72451458285b679649dc35d5cc8c18faf59436fb15d8acd5cdb9");
        ADD_CHECKPOINT(87500, "7ce8c46ec528c38ac6db3223a2826f6a0b99a953dd60c2d95814d59c9da8195f");
        ADD_CHECKPOINT(90000, "9c1221ea6fa2b0d0c8ca569a7dda65d3bf8add7e379a173069c7e5e70a7ced15");
        ADD_CHECKPOINT(92500, "631a533c26bb1871ab90df6267b903730adf3fdb4d32f421705a816cdb115338");
        ADD_CHECKPOINT(95000, "e972d54b93d46789cf277370d4bd1050e59bb7028d8519dc81bcdb47314e374d");
        ADD_CHECKPOINT(97500, "231b6114d1559775f7c6270a1d503a36e402a979702f1c39e30a3e7652810316");
        ADD_CHECKPOINT(100000, "ba153f120ecee2429bf7ad540852ccef4a4d668fa31ff2209c268136803124cc");
        ADD_CHECKPOINT(102500, "cadfec6c5d4764b6cbc2162bf59583dc6be5d5593524a799e0c6f76a7cd7a1d6");
        ADD_CHECKPOINT(105000, "e9bf9d89db3ec6a85729429a39f8bb67707f120be276c464e28bca0b850f6a83");
        ADD_CHECKPOINT(107500, "fa817a9c989929b2ded673a321ce3a7daa671104096e1afcfb85e4c88001dcaf");
        ADD_CHECKPOINT(110000, "f42d9770d4eb876913b9574cffd2fa76c615d93ec58d3c7a1b6ca4417c1d866d");
        ADD_CHECKPOINT(112500, "7b0a4ff9d31f82f3396766e08a738ea0e9536c146a918dcfe37f1db54e5afff8");
        ADD_CHECKPOINT(115000, "4914cdb8a5e059c5cb8c51753b83d1eb95a8012dfbecdba2c278df8cf95e4409");
        ADD_CHECKPOINT(117500, "3b164bcef55b1c06c28caf35da96ce2b57b520a01f8296bdab08fc73d1a68351");
        ADD_CHECKPOINT(120000, "f2b724e500a042839815f20378ee0bafdb7176b4fb48e2fe5764315385f4c445");
        ADD_CHECKPOINT(122500, "ac936d4fffdd047ed0ebbd6289afd67576388bbf579419009ba7b8e1f6d61a44");
        ADD_CHECKPOINT(125000, "ea39adf942d20496de022a028afb9d13cd1487c54047fcc3fa061772339cb274");
        ADD_CHECKPOINT(127500, "8d2cf4a89e856a818d41ce01b034ba53f96aeb9284f0185c69c9d0d5ce80183d");
        ADD_CHECKPOINT(130000, "8ef57ebdee0d14d9f362eb358b8d56d343bcbe8328d94879be8510d12d2300ab");
        ADD_CHECKPOINT(132500, "903b53239b081721c5201322ba32629b5e65b7176cf36afdd53410cb6fbc2fa7");
        ADD_CHECKPOINT(135000, "5df8ade863626bcc7ea9b33716ec0285b9403479e961e76dba08e9ec6b40931b");
        ADD_CHECKPOINT(137500, "2a6a083b2805f2518f48c3c0a175e0caaf0a4d4dc6d6c13e938cfa43c6f6c51b");
        ADD_CHECKPOINT(140000, "d473423a4686a8670e6cfdb3059d9a8c9014c493730a8c6f8116096ca17bd60d");
        ADD_CHECKPOINT(142500, "0175f015f4391b921e9f315898885260d1d00e9463cff3fdd5f7e11274c2d878");
        ADD_CHECKPOINT(145000, "a24d2e3d71f4baf2ecc60fea9b592a52936696f15ca755ebc63730017c7531d0");
        ADD_CHECKPOINT(147500, "a4a8bb89858659b6251db05c4b0db8cb293475c51d7d41f1361880f876ac24e5");
        ADD_CHECKPOINT(150000, "b38f36580cdbeadc0ddb970dff3c8645b6a0c7c67853e7f3fc3a33b143e547b9");
        ADD_CHECKPOINT(152500, "1cec35bd7df79a406e9373588cb41c9a8094a8be879bec9b9cc9b132950d73bc");
        ADD_CHECKPOINT(155000, "07b39a9c30cf357c639430b29e55909b7e9717d15e33d921294fa8d94f1bb71d");
        ADD_CHECKPOINT(157500, "2c147d484e3a845349f32941f668b76632a9c63b5203cbdb938f251852f7f6c7");
        ADD_CHECKPOINT(160000, "adbe4ccd46294bfe8fd511d12a680abdac241884db8610a0c035e3cadb883710");
        ADD_CHECKPOINT(162500, "e3677dc4790f8d5af4987e5728b66ef1852e360baf871c8b372bd098809f85ad");
        ADD_CHECKPOINT(165000, "1094b48650c664d7fe807cabc89177c8a47043a9de1ae63d894678986fe8b16a");
        ADD_CHECKPOINT(167500, "4cfe39f81bc9ad63236a6ac01824166946ba8510c375dbda69b20304d4ed152d");
        ADD_CHECKPOINT(170000, "da5e48763536f4da0e3d94f7a368347327053ded5599ddc2366afc575ab9ff98");
        ADD_CHECKPOINT(172500, "424de30ce25b4a5090ad96dd0b051963fb0a01c6a48a2600dcaa9b71448211f0");
        ADD_CHECKPOINT(175000, "79d36a75060bdd669eb2d2e8e97769028e6d2fe3c640d34cbf0803fded2f8e21");
        ADD_CHECKPOINT(177500, "8636593d07fb5b5851aa35d9ea884c71cca30b05ec994ee01ef254cf855874bf");
        ADD_CHECKPOINT(180000, "4c49bfc301f78dbbff61f95f70723aa282045f3a4bdb40318a1a40d709257e7d");
        ADD_CHECKPOINT(182500, "415cfd436316ffbcf56a69d6683ea79d8ef67758f25d3dcb13576e6e82541712");
        ADD_CHECKPOINT(185000, "b6ff4a2c68228d41c81a915f001ea0164b94809111de6f435bfc04aaa342e7a3");
        ADD_CHECKPOINT(187500, "ff9f293bd26cbebc40dd64464c3df5ae086b4ec265e4d95cccdd6ddfd0e99492");
        ADD_CHECKPOINT(190000, "c3d31fceea25f2a573f0f5e8150d9eed5bf4a7350c8911fb66b154d75165b098");
        ADD_CHECKPOINT(192500, "cf45c6f6420e5f0142febc17e2ab986cb65478f5bc16cc3e3c2ebb981f29cfc1");
        ADD_CHECKPOINT(195000, "f74ac85bb8ce3e6cb3bda7e94cdef70fd24bb663fd177ab923c8529dee20117e");
        ADD_CHECKPOINT(197500, "63c7be8e955cee9c4c67eac20ea229b9f3f318e9d0bb32735fa2c6cb8800ac68");
        ADD_CHECKPOINT(200000, "5f1f8e76978b93144c1faa184a4e550a600a0b469f16177412166b041804191f");
        ADD_CHECKPOINT(202500, "91620fe0347a3569ac9a891ac773c2b0698d4998a07e1b7e62739eb43ec8a847");
        ADD_CHECKPOINT(205000, "89a99b2df9e15aae5582468cb968215c85a60583cdc27829504d6a143e0eb515");
        ADD_CHECKPOINT(207500, "d30dc152a821fb0c8c36d77ef955a6f862ae03361dc63aad65f4a1a3c4cd60ec");
        ADD_CHECKPOINT(210000, "d52e7895856ca4d9dce97210e77797de5d9773c2d8dddfc0c6fe2dd1034455b6");
        ADD_CHECKPOINT(212500, "02f591e79337c2cee305cc9f2f573b5d7edb4156ad738ba53933a99e32b074a2");
        ADD_CHECKPOINT(215000, "f5ca35ff48a944eece762b97053a7e504fdd6b1c544cc2bad34aaa785b5b7607");
        ADD_CHECKPOINT(217500, "f9941f51e221461d95fc8eb216cf213b2ee348a2be9890aa08aa50531a162e84");
        ADD_CHECKPOINT(220000, "d09baec5747f4ef66013dc17ab82b18f0ffea582bcac24c57c9ab084d97e0946");
        ADD_CHECKPOINT(222500, "85ffa738085899251c6d4b1b18e451866087362a575250baefc38639ca69bd6f");
        ADD_CHECKPOINT(225000, "a869173ffd70a5e688e8615e274b06bd8bb16f2e3e12c65210dcd05426b2dfa4");
        ADD_CHECKPOINT(227500, "a5488c0049f9291ad5e8c4bc7432913dfa1894c4bd3e79f23715e1087e4989e4");
        ADD_CHECKPOINT(230000, "359f768acce20584a6285ae4f79f536187b73f6f5e15aeb686199c4fb27039d5");
        ADD_CHECKPOINT(232500, "3c6f1ada537595344e63195ade7c30c1106b81f7c21aa9e7f223d9bef8f90104");
        ADD_CHECKPOINT(235000, "8711e493888cca8656f3caa0bcc69636f89de53d1f2c9d48e53f981319f7c4b6");
        ADD_CHECKPOINT(237500, "f6074fbccffd31ae7cf8d0c71cf9da1e5c6a12305eb07c053ad555ffa9a81dd1");
        ADD_CHECKPOINT(240000, "7c5f53fe1ae474ba0dfde9c5d0ff51d0e37f432bfb8ebc1f74e32d8236dbc143");
        ADD_CHECKPOINT(242500, "b832a68417e10971b75edfaf458b30dd79034af92c616d508aed6a68b4fc1172");
        ADD_CHECKPOINT(245000, "3d213f61578c55699cf10cdc66d4d885712a196c725417b7b2d4a7e101c75d44");
        ADD_CHECKPOINT(247500, "d27e350b2493dc95206e5313179fa98f11242a5643d591969b475322fd9f29f3");
        ADD_CHECKPOINT(250000, "9c2d29ec599933f17c8ea546bd5dd17735028e4d0de3edd71dc5be97b23e3c54");
        ADD_CHECKPOINT(252500, "852e477786586664e472650555a14c879807e9b4928dee57d4392299db935715");
        ADD_CHECKPOINT(255000, "834e9964bad28d74b65caaf4426282fe37812e5c2d1a7fca8389dca7c031c8f1");
        ADD_CHECKPOINT(257500, "221909e0887c576ad797a8b7b92c9203de71eb6281a3fac53e1cfd33c4048c01");
        ADD_CHECKPOINT(260000, "7a1880b3b128bf9b2ef36a5529bfc0e55e92e8c6ff1acd7481d33eb4e27510df");
        ADD_CHECKPOINT(262500, "6a7cb6309be2209e051262742c15616fddd6543746157ce899914f99c0386533");
        ADD_CHECKPOINT(265000, "ecdb8c6286227607dbcbbb6c2df49c3a2799454245c7edbfaa37687afd822dce");
        ADD_CHECKPOINT(267500, "880e30032b9aec47cfdc488ce26f1e9369a1d15fdeb9d6e54069f46fd9d4bd27");
        ADD_CHECKPOINT(270000, "af28be2e9fffd11881b9f002ac4bdf29810d189d9cd3fffea404661094a695fe");
        ADD_CHECKPOINT(272500, "1b0f63dc61905754e294d66aeef14a27ff942314daa42600bf70d97f5041c6f1");
        ADD_CHECKPOINT(275000, "019e6cdd9efb02ed546a74f06700751e95fb2ecf8b8c318e8460a68ec7cbbce0");
        ADD_CHECKPOINT(277500, "a30d930c069ea8f27397236ed268e7868ee99eaefd5fac190be25204f560fd02");
        ADD_CHECKPOINT(280000, "e654ad8ace8c7100b65f99201cb907f2a6b730710001f8146c4a3766d16f6d03");
        ADD_CHECKPOINT(282500, "2f687c97fa7ff2baec5ea1e37cf3af2be736e2a9fc21230259dd054f256e1ee2");
        ADD_CHECKPOINT(285000, "5460ae91c7bbbf2a6387b84dc0645897358fde6c3d42af00dfcb78422bb44532");
        ADD_CHECKPOINT(287500, "c2cfa1a9b6f7be584eca192fa84853d25734cf30d95bdbb76ef0629779e87cfe");
        ADD_CHECKPOINT(290000, "411d2aa6c75a74e57b414fc3b5c0da9c29d54c870ee27f5d79dc99d313f7a78a");
        ADD_CHECKPOINT(292500, "a07545ee186c0c4054da71313e1132117c4221c6e39c0bd7cd8dd837c74c27ec");
    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if(!(boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if(!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for(std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    // All four GNTL Network domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = {

	};

    static const std::vector<std::string> testnet_dns_urls = {
    };

    static const std::vector<std::string> stagenet_dns_urls = {
    };

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return false; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::hex_to_pod(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
