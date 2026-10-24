{
  description = "secwatch - self-hosted security monitoring for small fleets (homelabs, small offices)";

  # Consumers can share their nixpkgs: inputs.secwatch.inputs.nixpkgs.follows = "nixpkgs";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      systems = [ "x86_64-linux" "aarch64-linux" ];
      # PolyForm Noncommercial is not a free licence in the nixpkgs sense; allow just this package
      pkgsFor = system: import nixpkgs {
        inherit system;
        config.allowUnfreePredicate = pkg: lib.getName pkg == "secwatch";
      };
      forAll = f: lib.genAttrs systems (system: f (pkgsFor system));
    in
    {
      packages = forAll (pkgs: rec {
        secwatch = pkgs.callPackage ./nix/package.nix { };
        default = secwatch;
      });

      # The module takes the package from this flake (self), never from pkgs.secwatch.
      nixosModules.default = import ./nix/module.nix { inherit self; };
      nixosModules.secwatch = self.nixosModules.default;

      checks = forAll (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        module = import ./nix/module-check.nix { inherit self nixpkgs pkgs; };
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: with ps; [ fastapi uvicorn httpx pyyaml jinja2 argon2-cffi pytest ]))
            pkgs.vulnix
            pkgs.trivy
          ];
        };
      });
    };
}
