/// Server UI for external debugging, either locally or remotely, via TCP.
///
/// This acts as a debugging server, useful for external applications, if
/// supported.
///
/// (TCP) Defaults to listen on localhost:3549. Input receives commands and
/// output is done via printf.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module ui.tcpserver;

