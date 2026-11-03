// The BusyBox persona for the Telnet service.
//
// Telnet on port 23 is probed by IoT botnets, Mirai above all, not by people.
// Those bots do not expect an Ubuntu server: they expect a camera or a router
// running BusyBox ash, and they fingerprint it before they act. This builds a
// command set that answers the way such a device does, on top of the same
// fake shell the SSH honeypot uses. Nothing is executed here either.
#pragma once

#include <arapuca/ssh/shell.hpp>

#include <string>

namespace arapuca::telnet {

/// The command set a logged in Telnet session gets. It is the ordinary command
/// registry with the handlers an embedded device answers differently: the
/// `busybox` applet probe, the `tftp` and `ftpget` downloaders, an embedded
/// `uname`, and the no-op shell escalations the bots try (`enable`, `system`,
/// `shell`). URLs still reach the capture engine, which is the point.
[[nodiscard]] ssh::CommandRegistry busybox_registry();

/// The line BusyBox prints when a shell is entered, shown after a successful
/// login. The version is a real BusyBox release, because the bots match on it.
[[nodiscard]] std::string busybox_shell_banner();

}  // namespace arapuca::telnet
