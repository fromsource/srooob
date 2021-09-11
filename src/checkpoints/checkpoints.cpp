// Copyright (c) 2021-2021, The GNTL Project
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
