/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <getopt.h>
#include <iostream>
#include <map>
#include <string.h>
#include <unistd.h>

#include <libudev.h>
#include <smartmontools/libsmartctl.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

std::vector<std::string> getBlkDevices() {
  std::vector<std::string> results;

  udev* ud = udev_new();
  if (!ud) {
    return results;
  }

  udev_enumerate* enumerate = udev_enumerate_new(ud);
  udev_enumerate_add_match_subsystem(enumerate, "block");
  udev_enumerate_scan_devices(enumerate);
  udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate);

  udev_list_entry* dev_list_entry;
  udev_list_entry_foreach(dev_list_entry, devices) {
    const char* path = udev_list_entry_get_name(dev_list_entry);
    if (!path) {
      continue;
    }
    if (strstr(path, "virtual")) {
      continue;
    }

    udev_device* dev = udev_device_new_from_syspath(ud, path);
    if (!dev) {
      continue;
    }

    results.push_back(udev_device_get_devnode(dev));
  }

  // free libudev objects;
  udev_enumerate_unref(enumerate);
  udev_unref(ud);

  return results;
}

QueryData genSmartDevInformation(QueryContext& context) {
  if (getuid() || geteuid()) {
    LOG(WARNING) << "Need root access for smart information";
  }

  QueryData results;
  libsmartctl::Client& c = libsmartctl::Client::getClient();

  std::vector<std::string> devs = getBlkDevices();
  for (auto const& dev : devs) {
    libsmartctl::DevInfoResp resp = c.getDevInfo(dev);
    if (resp.err != NOERR) {
      LOG(WARNING) << "There was an error retrieving drive information: "
                   << resp.err;
      return results;
    }

    resp.content["device_name"] = dev;
    results.push_back(resp.content);
  }

  return results;
}

QueryData genSmartDevVendorAttrs(QueryContext& context) {
  if (getuid() || geteuid()) {
    LOG(WARNING) << "Need root access for smart information";
  }

  QueryData results;
  libsmartctl::Client& c = libsmartctl::Client::getClient();

  std::vector<std::string> devs = getBlkDevices();
  for (auto const& dev : devs) {
    libsmartctl::DevVendorAttrsResp resp = c.getDevVendorAttrs(dev);
    if (resp.err != NOERR) {
      LOG(WARNING)
          << "There was an error retrieving smart drive vendor attributes: "
          << resp.err;
      return results;
    }
    // Walk thru attributes to append device name to each vendor attribute map
    // and append to results.
    for (auto& va : resp.content) {
      va["device_name"] = dev;
      results.push_back(va);
    }
  }

  return results;
}
}
}
