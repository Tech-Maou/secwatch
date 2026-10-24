# Evaluates the NixOS module in a few configurations and builds the generated unit files.
{ self, nixpkgs, pkgs }:

let
  eval = extra: (nixpkgs.lib.nixosSystem {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      self.nixosModules.default
      {
        boot.isContainer = true;
        system.stateVersion = "26.05";
        services.secwatch.enable = true;
      }
      extra
    ];
  }).config;

  standalone = eval {
    services.secwatch = {
      settings.notify.ntfy = { enabled = true; url = "https://ntfy.example.org"; topic = "secwatch"; };
      ntfy.tokenFile = "/run/secrets/ntfy-token";
      collectors.lynis.enable = false;
      nginx.virtualHost = "sec.example.org";
    };
    services.nginx.enable = true;
    virtualisation.podman.enable = true;
  };
  agent = eval {
    services.secwatch = {
      role = "agent";
      listen.address = "0.0.0.0";
      agentTokenFile = "/run/secrets/secwatch-agent";
      openFirewall = { enable = true; sources = [ "10.100.0.1" "fd00::1" ]; };
    };
  };
  hub = eval {
    services.secwatch = {
      role = "hub";
      agents = [{ name = "agent1"; url = "http://10.100.0.2:8478"; tokenFile = "/run/secrets/agent-home"; }];
    };
    networking.nftables.enable = true;
  };

  units = c: map (u: { name = "${c.networking.hostName or "x"}-${u}"; path = c.systemd.units.${u}.unit; })
    [ "secwatch-web.service" "secwatch-scan.service" "secwatch-scan.timer" "secwatch-scan.path" ];
  overrides = c: builtins.toJSON {
    env = c.systemd.services.secwatch-web.environment.SECWATCH_OVERRIDES;
    firewall = c.networking.firewall.extraCommands + c.networking.firewall.extraInputRules;
  };
in
pkgs.runCommand "secwatch-module-check" { } ''
  mkdir -p $out
  ${pkgs.lib.concatMapStrings (c: pkgs.lib.concatMapStrings (u: "cp -r ${u.path} $out/${u.name}-$RANDOM\n") (units c)) [ standalone agent hub ]}
  cp ${pkgs.writeText "standalone.json" (overrides standalone)} $out/standalone.json
  cp ${pkgs.writeText "agent.json" (overrides agent)} $out/agent.json
  cp ${pkgs.writeText "hub.json" (overrides hub)} $out/hub.json
  grep -q 'secwatch-scan scan --if-due' $out/*secwatch-scan.service*/secwatch-scan.service
  grep -q 'PathExists=/var/lib/secwatch/trigger' $out/*secwatch-scan.path*/secwatch-scan.path
  grep -q '10.100.0.1' $out/agent.json
  echo ok > $out/result
''
