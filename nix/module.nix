{ self }:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.secwatch;
  inherit (lib) mkOption mkEnableOption mkIf types optionalAttrs optionalString;

  collectorNames = [ "nix" "os" "containers" "lynis" "exposure" "secrets" "auth" "updates" "sbom" ];
  secretPath = types.nullOr (types.strMatching "^/.*");

  derived = lib.foldl' lib.recursiveUpdate { } ([
    {
      role = cfg.role;
      web = { listen = cfg.listen.address; port = cfg.listen.port; };
    }
    (optionalAttrs (cfg.nginx.virtualHost != null) {
      web.base_url = "https://${cfg.nginx.virtualHost}";
      web.secure_cookie = true;
    })
    (optionalAttrs (cfg.ntfy.tokenFile != null) { notify.ntfy.token_file = cfg.ntfy.tokenFile; })
    (optionalAttrs (cfg.mail.passwordFile != null) { notify.mail.password_file = cfg.mail.passwordFile; })
    (optionalAttrs (cfg.agentTokenFile != null) { agent.token_file = cfg.agentTokenFile; })
    (optionalAttrs (cfg.tokenFile != null) { web.token_file = cfg.tokenFile; })
    (optionalAttrs (cfg.agents != [ ]) {
      hub.agents = map (a: { inherit (a) name url; token_file = a.tokenFile; }) cfg.agents;
    })
  ] ++ lib.mapAttrsToList
    (name: c: optionalAttrs (c.enable != null) { collectors.${name}.enabled = c.enable; })
    cfg.collectors);

  # settings given here win over config.yaml and are shown read-only in the UI
  finalSettings = lib.recursiveUpdate derived cfg.settings;
  overridesFile = pkgs.writeText "secwatch-overrides.json"
    (builtins.toJSON { settings = finalSettings; locked = cfg.lockedKeys; });

  env = {
    SECWATCH_STATE_DIR = cfg.stateDir;
    SECWATCH_OVERRIDES = toString overridesFile;
    PYTHONDONTWRITEBYTECODE = "1";
  };

  commonHardening = {
    NoNewPrivileges = true;
    PrivateTmp = true;
    ProtectSystem = "strict";
    ReadWritePaths = [ cfg.stateDir ];
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    SystemCallArchitectures = "native";
    RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
    UMask = "0007";
  };

  port = toString cfg.listen.port;
  isV6 = s: lib.hasInfix ":" s;
in
{
  options.services.secwatch = {
    enable = mkEnableOption "secwatch security monitoring";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "secwatch.packages.\${system}.default (from the secwatch flake)";
      description = "secwatch package (taken from the secwatch flake, not from nixpkgs).";
    };

    role = mkOption {
      type = types.enum [ "standalone" "agent" "hub" ];
      default = "standalone";
      description = "standalone: scan and show this host; agent: also serve /api/agent/snapshot for a hub; hub: pull agents.";
    };

    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/secwatch";
      description = "State directory (database, config.yaml, reports, caches, trigger file).";
    };

    listen = {
      address = mkOption { type = types.str; default = "127.0.0.1"; description = "Web UI / API listen address."; };
      port = mkOption { type = types.port; default = 8478; description = "Web UI / API port."; };
    };

    settings = mkOption {
      type = types.attrsOf types.anything;
      default = { };
      example = lib.literalExpression ''{ notify.ntfy = { enabled = true; url = "https://ntfy.example.org"; topic = "secwatch"; }; }'';
      description = ''
        Settings merged into the configuration (same structure as config.yaml).
        Every key given here is locked: the web UI shows it read-only.
      '';
    };

    lockedKeys = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "notify.matrix" ];
      description = "Additional dotted config paths to lock (read-only in the UI) without setting them.";
    };

    collectors = lib.genAttrs collectorNames (name: {
      enable = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = "Enable/disable the ${name} collector (null = leave it to config.yaml/auto detection).";
      };
    });

    ntfy.tokenFile = mkOption { type = secretPath; default = null; description = "File with the ntfy access token (not in the Nix store)."; };
    mail.passwordFile = mkOption { type = secretPath; default = null; description = "File with the SMTP password (not in the Nix store)."; };
    tokenFile = mkOption { type = secretPath; default = null; description = "File with an API/login token for the web UI (alternative to the admin password)."; };
    agentTokenFile = mkOption { type = secretPath; default = null; description = "Agent role: file with the bearer token the hub must present."; };

    agents = mkOption {
      description = "Hub role: agents to pull snapshots from.";
      default = [ ];
      type = types.listOf (types.submodule {
        options = {
          name = mkOption { type = types.strMatching "^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$"; description = "Host name shown on the hub."; };
          url = mkOption { type = types.strMatching "^https?://.*"; description = "Base URL of the agent's secwatch-web."; };
          tokenFile = mkOption { type = types.strMatching "^/.*"; description = "File with the agent's bearer token."; };
        };
      });
    };

    openFirewall = {
      enable = mkEnableOption "opening the web/agent port in the firewall";
      sources = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "10.100.0.1" "192.168.1.0/24" ];
        description = "Only allow these source addresses/CIDRs (e.g. the hub). Empty = everybody.";
      };
    };

    nginx = {
      virtualHost = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "sec.example.org";
        description = "Create an nginx virtual host proxying to secwatch-web (TLS/ACME via virtualHostConfig).";
      };
      virtualHostConfig = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        example = lib.literalExpression ''{ forceSSL = true; useACMEHost = "example.org"; }'';
        description = "Extra attributes merged into the nginx virtual host.";
      };
    };

    timerOnCalendar = mkOption {
      type = types.str;
      default = "*:0/15";
      description = ''
        How often secwatch-scan wakes up. The actual scan/report schedule comes from the
        configuration (wizard/settings); the wake-up only checks what is due.
      '';
    };

    extraScanPackages = mkOption {
      type = types.listOf types.package;
      default = [ ];
      example = lib.literalExpression "[ pkgs.lynis pkgs.gitleaks ]";
      description = "Extra tools on the scan service PATH (phase-2 collectors: lynis, gitleaks).";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      { assertion = cfg.role != "agent" || cfg.agentTokenFile != null || (finalSettings.agent.token_file or "") != "";
        message = "services.secwatch: role = \"agent\" needs agentTokenFile."; }
      { assertion = cfg.role == "hub" || cfg.agents == [ ];
        message = "services.secwatch.agents is only used with role = \"hub\"."; }
      { assertion = !(lib.any (p: p != null && lib.hasPrefix "/nix/store" p) [ cfg.ntfy.tokenFile cfg.mail.passwordFile cfg.tokenFile cfg.agentTokenFile ]);
        message = "services.secwatch: secret files must not live in the Nix store."; }
    ];
    warnings = lib.optional (cfg.openFirewall.enable && lib.elem cfg.listen.address [ "127.0.0.1" "::1" "localhost" ])
      "services.secwatch.openFirewall is enabled but listen.address is ${cfg.listen.address}; the port is not reachable from outside.";

    users.users.secwatch = {
      isSystemUser = true;
      group = "secwatch";
      home = cfg.stateDir;
      description = "secwatch web UI";
    };
    users.groups.secwatch = { };

    # setgid: files written by the root scan service belong to group secwatch (web can read/write)
    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 2770 secwatch secwatch - -"
      "d ${cfg.stateDir}/reports 2770 secwatch secwatch - -"
      "d ${cfg.stateDir}/cache 2770 secwatch secwatch - -"
      "d ${cfg.stateDir}/secrets 2770 secwatch secwatch - -"
    ];

    environment.systemPackages = [ cfg.package ];

    systemd.services.secwatch-web = {
      description = "secwatch web UI and API";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "systemd-tmpfiles-setup.service" ];
      environment = env;
      path = [ pkgs.iproute2 config.systemd.package ];
      serviceConfig = commonHardening // {
        ExecStart = "${cfg.package}/bin/secwatch-web --host ${cfg.listen.address} --port ${port}"
          + optionalString (cfg.nginx.virtualHost != null) " --proxy-headers";
        User = "secwatch";
        Group = "secwatch";
        Restart = "on-failure";
        RestartSec = 5;
        ProtectHome = true;
        PrivateDevices = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
        MemoryMax = "512M";
      };
    };

    systemd.services.secwatch-scan = {
      description = "secwatch scanner (collectors, enrichers, reports, notifications)";
      after = [ "network-online.target" "systemd-tmpfiles-setup.service" ];
      wants = [ "network-online.target" ];
      environment = env // { NIX_REMOTE = "daemon"; HOME = "${cfg.stateDir}/cache"; };
      path = [ pkgs.vulnix pkgs.trivy pkgs.iproute2 config.nix.package config.systemd.package pkgs.coreutils ]
        ++ lib.optional config.virtualisation.podman.enable config.virtualisation.podman.package
        ++ lib.optional config.virtualisation.docker.enable config.virtualisation.docker.package
        ++ cfg.extraScanPackages;
      serviceConfig = commonHardening // {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/secwatch-scan scan --if-due";
        User = "root";
        Group = "secwatch";
        SupplementaryGroups = [ "systemd-journal" ];
        ProtectHome = "read-only";
        # read everything (trivy rootfs, journald, ss -p), write only the state dir
        CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" "CAP_DAC_OVERRIDE" "CAP_FOWNER" "CAP_CHOWN" "CAP_SYS_PTRACE" "CAP_NET_ADMIN" ];
        SystemCallFilter = [ "@system-service" ];
        Nice = 10;
        IOSchedulingClass = "idle";
        TimeoutStartSec = "4h";
      };
    };

    systemd.timers.secwatch-scan = {
      description = "secwatch scheduler wake-up";
      wantedBy = [ "timers.target" ];
      timerConfig = { OnCalendar = cfg.timerOnCalendar; Persistent = true; RandomizedDelaySec = 30; };
    };

    # "Scan now" / "send test" in the UI write the trigger file
    systemd.paths.secwatch-scan = {
      description = "secwatch scan trigger";
      wantedBy = [ "paths.target" ];
      pathConfig = { PathExists = "${cfg.stateDir}/trigger"; Unit = "secwatch-scan.service"; };
    };

    # containers collector talks to the engine socket (never pulls images)
    systemd.sockets.podman = mkIf (config.virtualisation.podman.enable && cfg.collectors.containers.enable != false) {
      wantedBy = [ "sockets.target" ];
    };

    services.nginx.virtualHosts = mkIf (cfg.nginx.virtualHost != null) {
      ${cfg.nginx.virtualHost} = lib.mkMerge [
        {
          locations."/" = {
            proxyPass = "http://${if cfg.listen.address == "0.0.0.0" then "127.0.0.1" else cfg.listen.address}:${port}";
            recommendedProxySettings = true;
          };
        }
        cfg.nginx.virtualHostConfig
      ];
    };

    networking.firewall = mkIf cfg.openFirewall.enable (
      if cfg.openFirewall.sources == [ ] then { allowedTCPPorts = [ cfg.listen.port ]; }
      else if config.networking.nftables.enable then {
        extraInputRules = lib.concatMapStrings
          (s: "ip${optionalString (isV6 s) "6"} saddr ${s} tcp dport ${port} accept comment \"secwatch\"\n")
          cfg.openFirewall.sources;
      } else {
        extraCommands = lib.concatMapStrings
          (s: "${if isV6 s then "ip6tables" else "iptables"} -A nixos-fw -p tcp -s ${s} --dport ${port} -j nixos-fw-accept\n")
          cfg.openFirewall.sources;
      }
    );
  };
}
