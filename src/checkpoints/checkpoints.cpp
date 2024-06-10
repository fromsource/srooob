// Copyright (c) 2021-2024, The GNTL Project
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
        ADD_CHECKPOINT(0, "4010c82bbd835d9580dd95fdcd0834d90102782f06016c9f069a2303ddc682e0");
        ADD_CHECKPOINT(500, "3c2284b0b71ab000436e254df7b6c11bb460484d180f014aa3d21dfcbf9d0b5e");
      return true;
    }
        ADD_CHECKPOINT(0, "4010c82bbd835d9580dd95fdcd0834d90102782f06016c9f069a2303ddc682e0");
        ADD_CHECKPOINT(20000, "9dab170d2bf1b8832af876b610fefe0aa4e8f9e5031746c2804ecae15967e560");
        ADD_CHECKPOINT(40000, "455ebe7cb764770bf5e69bf4f681ef1cefdc48d98b879bde5e24276e2265b3b2");
        ADD_CHECKPOINT(60000, "11faca63b82439d23dc763a9e8d5dd6edac412ba667d48a925404c9041751204");
        ADD_CHECKPOINT(80000, "b709d6fd9874287ca013c7fc8560eb625d190420566c1b229e5989f8cebc375e");
        ADD_CHECKPOINT(100000, "ba153f120ecee2429bf7ad540852ccef4a4d668fa31ff2209c268136803124cc");
        ADD_CHECKPOINT(120000, "f2b724e500a042839815f20378ee0bafdb7176b4fb48e2fe5764315385f4c445");
        ADD_CHECKPOINT(140000, "d473423a4686a8670e6cfdb3059d9a8c9014c493730a8c6f8116096ca17bd60d");
        ADD_CHECKPOINT(160000, "adbe4ccd46294bfe8fd511d12a680abdac241884db8610a0c035e3cadb883710");
        ADD_CHECKPOINT(180000, "4c49bfc301f78dbbff61f95f70723aa282045f3a4bdb40318a1a40d709257e7d");
        ADD_CHECKPOINT(200000, "5f1f8e76978b93144c1faa184a4e550a600a0b469f16177412166b041804191f");
        ADD_CHECKPOINT(220000, "d09baec5747f4ef66013dc17ab82b18f0ffea582bcac24c57c9ab084d97e0946");
        ADD_CHECKPOINT(240000, "7c5f53fe1ae474ba0dfde9c5d0ff51d0e37f432bfb8ebc1f74e32d8236dbc143");
        ADD_CHECKPOINT(260000, "7a1880b3b128bf9b2ef36a5529bfc0e55e92e8c6ff1acd7481d33eb4e27510df");
        ADD_CHECKPOINT(280000, "e654ad8ace8c7100b65f99201cb907f2a6b730710001f8146c4a3766d16f6d03");
        ADD_CHECKPOINT(300000, "d80a3d8d3f1c0f7ae73d8a142e44132c68370fe157beeb9c9f8006d1fde56f6f");
        ADD_CHECKPOINT(320000, "ddf9b71ba3a9df8dd145830e0762ae40162a67f6787894480f58711ae7915ae6");
        ADD_CHECKPOINT(340000, "1f6f6865cfff350668a168349944f4a8e0387c4b6f3d046c26f40c1637a5281b");
        ADD_CHECKPOINT(360000, "745df5394ac24a8543b75d4d998cd5c922e1caca115a7a870216279ad3c49979");
        ADD_CHECKPOINT(380000, "0a297745d14db5d80a51a56f559a338383bb3b87bf6ed0bf48b1de1c85c9a195");
        ADD_CHECKPOINT(400000, "560a2f0d18725049925e8e5e2bad7d4720ba8f98c0d0d0732a2922be84f15097");
        ADD_CHECKPOINT(420000, "dc63bb7e0a575b723994cff4be4e1a3ccf08aabbd0caf6fddabcfcfa1e00eb77");
        ADD_CHECKPOINT(440000, "76f70c1f285ffd95ad8691184b477f1c9ca2ee19a502d15acada9dda3512c2b1");
        ADD_CHECKPOINT(460000, "9742afbacb499b76cec2fffba90dceaabc3452e8861e99597d31d097154f57e4");
        ADD_CHECKPOINT(480000, "e612b74505e68b6e4a368c5bab4aea471543b5b09139a798a93c5e857ab502c0");
        ADD_CHECKPOINT(500000, "8206873f79cc5118883a52a7ee29b31a543ff8b8e1915e9fd80e3b8477702db2");
        ADD_CHECKPOINT(520000, "5d655cabb45a74470212ab373faeb6acaa472a6911eadf161afdb6a662392ed9");
        ADD_CHECKPOINT(540000, "0be7bd8f542fa9be5c365bde65c954db64d11c832dc312bbac33de59f5ba8dcb");
        ADD_CHECKPOINT(560000, "43ce86ac676f89dc74793e8f511f1a0a6addfecee08f8e7561f490f184a4cd69");
        ADD_CHECKPOINT(580000, "edd9e756551e1eada2e124b7601fbe5c49ed8e4081b1feddcbd1e128461df7bf");
        ADD_CHECKPOINT(600000, "fd8b36a4486a5c7232e56c5806d9d2d29da7c4f2f05380f480dca824f083e783");
        ADD_CHECKPOINT(620000, "07e0c60523296c4d8d215f0fcb6ffb1e6ae24ad1c5b7d5650b7645c78e31b33a");
        ADD_CHECKPOINT(640000, "147469676e714e7c8eb1d1c414dfbd6c9af89e947eebdd661d11beface601a7d");
        ADD_CHECKPOINT(660000, "a5b429f0c0608fc4bb03175cf319fb2de6ecb8a724d82e216f5d2cb04f9c00b2");
        ADD_CHECKPOINT(680000, "6e21e404b09fa896222f4066b74ad6da4669b24daeb49ee64261b3822f820a57");
        ADD_CHECKPOINT(700000, "028a9f34a57c910105106c390a199aa5aa03305a8f4f7c2892b0921a7ccec12e");
        ADD_CHECKPOINT(720000, "f30f4d52135ae6cf76767d2381336c8e942cd67ef7dd3594a13d4ffdf345aa2d");
        ADD_CHECKPOINT(740000, "65f8f91f104a9b47e8be4b96e5a5e05a4a145df41f8c43544334955244313330");
        ADD_CHECKPOINT(760000, "65ade718431c5a8ae5e619443fa4da2f1841181977e2d9957be37a696459dd94");
        ADD_CHECKPOINT(780000, "174454115fc873190e96f45aaa0f19e2811cfeeac752d179f8d10d2d682060c5");
        ADD_CHECKPOINT(800000, "cfdc59811342df87950302066739511a88a54089e3bfdb100d40499aaea1cb96");
        ADD_CHECKPOINT(820000, "1e50f0bac61878ba7b18e0a2f5f23e50e5b98ec544c9938a6e92431116c3a57c");
        ADD_CHECKPOINT(840000, "5be0edc65af894756df29285e944dc9fdb64ebc6e22cad1b1c6d538029db7ed3");
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
