/**
 * Server UI for external debugging, either locally or remotely, via TCP.
 *
 * This acts as a debugging server, useful for external applications, if
 * supported.
 *
 * (TCP) Defaults to listen on localhost:3549. Input receives commands and
 * output is done via printf.
 *
 * License: BSD 3-clause
 */
module debugger.ui.server;

