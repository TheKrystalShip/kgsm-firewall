using TheKrystalShip.KGSM.ComponentConfig;

// What a person may do with this authority, through the node's API: the API checks it before it relays to
// the socket, so it is declared here, where it is performed, and checked there.
[assembly: Action("firewall:rules.read", "See which ports this machine has open, and for what",
    DeclaredEffect.Read, DeclaredScope.Node)]
