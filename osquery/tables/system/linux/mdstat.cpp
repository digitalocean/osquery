/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fstream>

#include <osquery/logger.h>

#include <osquery/core/conversions.h>

namespace osquery {
namespace tables {

std::string kMDStatPath = "/proc/mdstat";

struct MDDevice {
  std::string name;
  std::string status;
  std::string raidLevel;
  std::string usableSize;
  std::string other;
  std::vector<std::string> drives;
  std::string healthyDrives;
  std::string driveStatuses;
  std::string recovery;
  std::string resync;
  std::string bitmap;
  std::string checkArray;
};

struct MDStat {
  std::string personalities;
  std::vector<MDDevice> devices;
  std::string unused;
};

/**
 * @brief Removes prefixing and suffixing character
 *
 * @param s reference to target string
 * @param c character to remove
 *
 */
void trimStr(std::string& s, const char c = ' ') {
  std::size_t first = s.find_first_not_of(c);
  if (first == std::string::npos) {
    return;
  }

  std::size_t last = s.find_last_not_of(c);
  // erase last first b/c length change does not effect the beginning of string
  if (last < s.size() - 1) {
    s.erase(last + 1, std::string::npos);
  }

  s.erase(0, first);
}

/**
 * @brief Removes prefixing and suffixing character from each string in vector
 *
 * @param strs reference to vector of target strings
 * @param c character to remove
 *
 */
void trimStr(std::vector<std::string>& strs, const char c = ' ') {
  for (auto& s : strs) {
    trimStr(s, c);
  }
}

inline void getLines(std::vector<std::string>& lines) {
  std::ifstream handle(kMDStatPath);

  std::string line;
  if (handle.is_open()) {
    while (getline(handle, line)) {
      trimStr(line);

      if (line.find_first_not_of("\t\r\v ") != std::string::npos) {
        lines.push_back(line);
      }
    }

    handle.close();
  }
}

/**
 * @brief Parse mdstat text blob into MDStat struct
 *
 * @param result reference to a MDStat struct to store results into
 *
 * This function makes assumption about the structure of the mdstat text blobs.
 * If the structure is not what it expects, the logs a warning message and
 * moves on.
 *
 */
void parseMDStat(MDStat& result) {
  // Will be used to determine starting point of lines to work on.
  size_t n = 0;

  std::vector<std::string> lines;
  getLines(lines);

  if (lines.size() < 1) {
    return;
  }

  // This should always evaluate to true, but just in case we check.
  if (lines[0].find("Personalities :") != std::string::npos) {
    result.personalities = lines[0].substr(sizeof("Personalities :") - 1);
    n = 1;

  } else {
    LOG(WARNING) << "mdstat Personalites not found at line 0: " << lines[0]
                 << "\n";
  }

  while (n < lines.size()) {
    // Work off of first 2 character instead of just the first to be safe.
    std::string firstTwo = lines[n].substr(0, 2);
    // std::cout << "firstTwo is: '" << firstTwo << "'\n";
    if (firstTwo == "md") {
      std::vector<std::string> mdline = split(lines[n], ":", 1);
      if (mdline.size() < 2) {
        LOG(WARNING) << "Unexpected md device line structure: " << lines[n]
                     << "\n";
        continue;
      }

      MDDevice mdd;
      mdd.name = mdline[0];
      trimStr(mdd.name);

      std::vector<std::string> settings = split(mdline[1], " ");
      trimStr(settings);
      // First 2 of settings are always status and RAID level
      if (settings.size() >= 2) {
        mdd.status = settings[0];
        mdd.raidLevel = settings[1];

        for (size_t i = 2; i < settings.size(); i++) {
          mdd.drives.push_back(settings[i]);
        }
      }

      /* Next line is device config and settings.  We handle here instead of
       * later b/c pieces are need for both md_drives and md_devices table */
      std::vector<std::string> configline = split(lines[n + 1]);
      if (configline.size() < 4) {
        LOG(WARNING) << "Unexpected md device config: " << lines[n + 1] << "\n";

      } else {
        trimStr(configline);
        mdd.usableSize = configline[0] + " " + configline[1];
        mdd.healthyDrives = configline[configline.size() - 2];
        mdd.driveStatuses = configline[configline.size() - 1];

        if (configline.size() > 4) {
          for (size_t i = 2; i < configline.size() - 2; i++) {
            mdd.other += (" " + configline[i]);
          }
        }
      }
      // Skip config line for next iteration
      n += 1;

      // Handle potential bitmap, recovery, and resync lines
      std::size_t pos;
      while (true) {
        if ((pos = lines[n + 1].find("recovery =")) != std::string::npos) {
          mdd.recovery = lines[n + 1].substr(pos + sizeof("recovery =") - 1);
          trimStr(mdd.recovery);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("resync =")) != std::string::npos) {
          mdd.resync = lines[n + 1].substr(pos + sizeof("resync =") - 1);
          trimStr(mdd.resync);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("check =")) != std::string::npos) {
          mdd.checkArray = lines[n + 1].substr(pos + sizeof("check =") - 1);
          trimStr(mdd.checkArray);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("bitmap:")) != std::string::npos) {
          mdd.bitmap = lines[n + 1].substr(pos + sizeof("bitmap:") - 1);
          trimStr(mdd.bitmap);
          // Add an extra line for next iteration if so..
          n += 1;
          // If none of above, then we can break out of loop
        } else {
          break;
        }
      }

      result.devices.push_back(mdd);

      // Assume unused
    } else if (firstTwo == "un") {
      result.unused = lines[n].substr(sizeof("unused devices:") - 1);

      // Unexpected mdstat line, log a warning...
    } else {
      LOG(WARNING) << "Unexpected mdstat line: " << lines[n] << "\n";
    }

    n += 1;
  }
}

QueryData genMDDevices(QueryContext& context) {
  QueryData results;
  MDStat mds;

  parseMDStat(mds);
  for (auto& device : mds.devices) {
    Row r;
    r["device_name"] = device.name;
    r["status"] = device.status;
    r["raid_level"] = device.raidLevel;
    r["healthy_drives"] = device.healthyDrives;
    r["usable_size"] = device.usableSize;

    // Handle recovery & resync
    /* Make assumption that recovery/resync format is [d+]% ([d+]/[d+])
     * finish=<duration> speed=<rate> */
    auto handleR = [&r](std::string& line, std::string prefix) {
      std::vector<std::string> pieces(split(line, " "));
      if (pieces.size() != 4) {
        LOG(WARNING) << "Unexpected recovery/resync line format: " << line
                     << "\n";
        return;
      }
      trimStr(pieces);

      r[prefix + "_progress"] = pieces[0] + " " + pieces[1];

      std::size_t start = pieces[2].find_first_not_of("finish=");
      if (start != std::string::npos) {
        r[prefix + "_finish"] = pieces[2].substr(start);
      } else {
        r[prefix + "_finish"] = pieces[2];
      }

      start = pieces[3].find_first_not_of("speed=");
      if (start != std::string::npos) {
        r[prefix + "_speed"] = pieces[3].substr(start);
      } else {
        r[prefix + "_speed"] = pieces[3];
      }
    };

    if (device.recovery != "") {
      handleR(device.recovery, "discovery");
    }

    if (device.resync != "") {
      handleR(device.resync, "resync");
    }

    if (device.checkArray != "") {
      handleR(device.checkArray, "check_array");
    }

    if (device.bitmap != "") {
      std::vector<std::string> bitmapInfos(split(device.bitmap, ","));
      if (bitmapInfos.size() < 2) {
        LOG(WARNING) << "Unexpected bitmap line structure: " << device.bitmap
                     << "\n";
      } else {
        trimStr(bitmapInfos);
        r["bitmap_on_mem"] = bitmapInfos[0];
        r["bitmap_chunk_size"] = bitmapInfos[1];

        std::size_t pos;
        if (bitmapInfos.size() > 2 &&
            (pos = bitmapInfos[2].find("file:")) != std::string::npos) {
          r["bitmap_external_file"] =
              bitmapInfos[2].substr(pos + sizeof("file:") - 1);
          trimStr(r["bitmap_external_file"]);
        }
      }
    }

    r["unused_devices"] = mds.unused;

    results.push_back(r);
  }

  return results;
}

QueryData genMDDrives(QueryContext& context) {
  QueryData results;
  MDStat mds;

  parseMDStat(mds);

  for (auto& device : mds.devices) {
    for (auto& drive : device.drives) {
      std::size_t start = drive.find('[');
      if (start == std::string::npos) {
        LOG(WARNING) << "Unexpected device name format: " << drive << "\n";
        continue;
      }

      std::size_t end = drive.find(']');
      if (end == std::string::npos) {
        LOG(WARNING) << "Unexpected device name format: " << drive << "\n";
        continue;
      }

      Row r;
      r["md_device_name"] = device.name;
      r["drive_name"] = drive;
      // Assume last char of device name is ']'
      int driveNum = std::stoi(drive.substr(start + 1, end - start - 1));
      if (0 <= driveNum < device.driveStatuses.length() - 2) {
        device.driveStatuses[driveNum + 1] == 'U' ? r["status"] = "1"
                                                  : r["status"] = "0";

      } else {
        LOG(WARNING) << "Drive number is out of range of expected range: got ->"
                     << driveNum << "; expected max -> "
                     << device.driveStatuses.length() - 2 << "\n";
      }

      results.push_back(r);
    }
  }

  return results;
}

QueryData genMDPersonalities(QueryContext& context) {
  QueryData results;
  MDStat mds;

  parseMDStat(mds);

  std::vector<std::string> enabledPersonalities = split(mds.personalities, " ");
  for (auto& setting : enabledPersonalities) {
    trimStr(setting);
    std::string name(setting.substr(1, setting.length() - 2));
    Row r = {{"name", name}};

    results.push_back(r);
  }

  return results;
}
}
}
