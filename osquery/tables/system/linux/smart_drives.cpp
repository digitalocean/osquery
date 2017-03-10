/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <functional>
#include <getopt.h>
#include <iostream>
#include <map>
#include <string.h>
#include <unistd.h>

#include <libudev.h>
#include <smartmontools/libsmartctl.h>
#include <smartmontools/smartctl_errs.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/linux/udev.h"

namespace osquery {
namespace tables {

struct hwSmartCtl {
  const char* driver;
  int maxID;
};

// Look-up table for driver to smartctl controller name.
static const std::map<std::string, std::string> kSWDriverToClter = {
    {"ahci", "sat"},
};

static const std::map<std::string, hwSmartCtl> kHWDriverToClter = {
    {"megaraid_sas", hwSmartCtl{"megaraid,", 127}},
    {"hpsa", hwSmartCtl{"cciss,", 14}},
};

void walkUdevSubSystem(
    std::string subsystem,
    std::function<void(udev_list_entry*, udev*)> handleDevF) {
  auto delUdev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(delUdev)> ud(udev_new(), delUdev);

  if (ud.get() == nullptr) {
    LOG(ERROR) << "Could not get libudev handle";
    return;
  }

  auto delUdevEnum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(delUdevEnum)> enumerate(
      udev_enumerate_new(ud.get()), delUdevEnum);

  // udev_enumerate* enumerate = udev_enumerate_new(ud.get());
  udev_enumerate_add_match_subsystem(enumerate.get(), subsystem.c_str());
  udev_enumerate_scan_devices(enumerate.get());
  udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate.get());

  udev_list_entry* dev_list_entry;
  udev_list_entry_foreach(dev_list_entry, devices) {
    handleDevF(dev_list_entry, ud.get());
  }
}

std::vector<std::string> getBlkDevices() {
  std::vector<std::string> results;

  walkUdevSubSystem("block", [&results](udev_list_entry* entry, udev* ud) {
    const char* path = udev_list_entry_get_name(entry);
    if (path == nullptr) {
      return;
    }
    if (strstr(path, "virtual")) {
      return;
    }

    udev_device* dev = udev_device_new_from_syspath(ud, path);
    if (dev == nullptr) {
      return;
    }

    results.push_back(udev_device_get_devnode(dev));
  });

  return results;
}

std::vector<std::string> getStorageCtlerClassDrivers() {
  std::vector<std::string> results;

  walkUdevSubSystem("pci", [&results](udev_list_entry* entry, udev* ud) {
    const char* path = udev_list_entry_get_name(entry);
    if (!path) {
      return;
    }

    udev_device* device = udev_device_new_from_syspath(ud, path);
    if (UdevEventPublisher::getValue(device, "ID_PCI_CLASS_FROM_DATABASE") ==
        "Mass storage controller") {
      std::string driverName = UdevEventPublisher::getValue(device, "DRIVER");

      auto i = std::lower_bound(results.begin(), results.end(), driverName);
      if (i == results.end() || driverName < *i) {
        results.insert(i, driverName);
      }
    }
  });

  return results;
}

bool getSmartCtlDeviceType(std::vector<std::string> const& storageDrivers,
                           std::string& type,
                           int& count) {
  switch (storageDrivers.size()) {
  case 1:
    try {
      kSWDriverToClter.at(storageDrivers[0]);
      // No need to do anything if is sw storage controller.
      type = "";
      return true;
    } catch (std::out_of_range) {
      // Assume is not a sw driver, move on...
    }

    try {
      hwSmartCtl hwc(kHWDriverToClter.at(storageDrivers[0]));
      type = hwc.driver;
      count = hwc.maxID;
      return true;
    } catch (std::out_of_range) {
      LOG(WARNING) << "Driver not supported: " << storageDrivers[0];
      // if none is found, none is supported.
      return false;
    }

  case 2: {
    std::string swc;
    hwSmartCtl hwc;
    auto getTypes = [&](int i, int j) -> bool {
      try {
        swc = kSWDriverToClter.at(storageDrivers[i]);
        hwc = kHWDriverToClter.at(storageDrivers[j]);
        count = hwc.maxID;
        type = swc + "+" + std::string(hwc.driver);
        return true;

      } catch (std::out_of_range) {
        return false;
      }
    };
    // With current supported set of drivers, this should always hit.
    if (getTypes(0, 1)) {
      return true;
    }

    if (!getTypes(1, 0)) {
      LOG(WARNING) << "Unsupported combination of storage controller drivers "
                      "(when more than 1): one must be ahci and one must be a "
                      "hardware RAID controller";
      return false;
    }
  }

  default:
    LOG(WARNING) << "Cannot support more than 2 unique driver combinations";
    return false;
  }

  return true;
}

void walkSmartDevices(std::function<void(libsmartctl::Client&,
                                         std::string const& devname,
                                         std::string const& type,
                                         int deviceId)> handleDevF) {
  if (getuid() || geteuid()) {
    LOG(WARNING) << "Need root access for smart information";
  }

  QueryData results;
  libsmartctl::Client& c = libsmartctl::Client::getClient();

  std::vector<std::string> storageDrivers = getStorageCtlerClassDrivers();
  int count = 0;
  std::string type;
  if (!getSmartCtlDeviceType(storageDrivers, type, count)) {
    // Logging handled in called function.
    return;
  }

  std::vector<std::string> devs = getBlkDevices();
  for (auto const& dev : devs) {
    if (type != "") {
      // if type is not null can skip the partitions
      if (dev.find_first_of("0123456789") != std::string::npos) {
        continue;
      }

      for (int i = 0; i < count; i++) {
        std::string fullType = std::string(type) + std::to_string(i);

        libsmartctl::CantIdDevResp cantId = c.cantIdDev(dev, fullType);
        if (cantId.err != NOERR) {
          LOG(WARNING) << "Error while trying to identify device";
          continue;
        }
        // if device is not identifiable, the type is invalid, skip
        if (!cantId.content) {
          handleDevF(c, dev, fullType, i);
        }
      }

      continue;
    }

    handleDevF(c, dev, type, -1);
  }
}

QueryData genSmartDevInformation(QueryContext& context) {
  QueryData results;

  walkSmartDevices([&results](libsmartctl::Client& c,
                              const std::string& dev,
                              std::string const& type,
                              int i) {
    libsmartctl::DevInfoResp resp = c.getDevInfo(dev, type);
    if (resp.err != NOERR) {
      LOG(WARNING) << "There was an error retrieving drive information: "
                   << resp.err;
      return;
    }

    if (i > -1) {
      resp.content["device_id"] = std::to_string(i);
    }

    resp.content["device_name"] = dev;
    results.push_back(resp.content);
  });

  return results;
}

QueryData genSmartDevVendorAttrs(QueryContext& context) {
  QueryData results;

  walkSmartDevices([&results](libsmartctl::Client& c,
                              const std::string& dev,
                              std::string const& type,
                              int i) {
    libsmartctl::DevVendorAttrsResp resp = c.getDevVendorAttrs(dev, type);
    if (resp.err != NOERR) {
      LOG(WARNING)
          << "There was an error retrieving smart drive vendor attributes: "
          << resp.err;
      return;
    }
    // Walk thru attributes to append device name to each vendor attribute map
    // and append to results.
    for (auto& va : resp.content) {
      if (i > -1) {
        va["device_id"] = std::to_string(i);
      }

      va["device_name"] = dev;
      results.push_back(va);
    }
  });

  return results;
}
}
}
