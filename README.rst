Trivial TCP4 Tunnels (ttt)
==========================

This software provides TCP4 traffic tunneling via https (connect)
or socks[45] proxies utilizing (usually) LD_PRELOAD of a dynamic
loaded to intercept connect(2) and bind(3) (system) calls.

This is no way a generic method, but works in some specific cases.

YMMV.

Before installing you can try to run ``./ttt`` to get some usage
information.


Usage example (creating socks proxy using ssh and then 2 cases to use it):
::

  terminal-0$ ttt ssh example.org

  terminal-1$ ttt us git pull

  terminal-2$ ttt cbi https://second.example.org/


Note that ``ssh`` tunneling also transforms attempt to bind INET socket
to binding UNIX socket. ``ttt us`` and ``ttt cbi`` transforms the connect
to do the same. With https proxy (running on remote host) this is somewhat
harder to do ;)
