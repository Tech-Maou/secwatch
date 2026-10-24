{ lib, python3Packages }:

python3Packages.buildPythonApplication {
  pname = "secwatch";
  version = "0.1.0";
  pyproject = true;

  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let base = baseNameOf path; in
      lib.cleanSourceFilter path type
      && !(lib.elem base [ ".venv" "state" "result" "docker" "systemd" "nix" "flake.nix" "flake.lock" "__pycache__" ".pytest_cache" ]);
  };

  build-system = [ python3Packages.setuptools ];

  dependencies = with python3Packages; [
    fastapi
    uvicorn
    httpx
    pyyaml
    jinja2
    argon2-cffi
  ];

  nativeCheckInputs = [ python3Packages.pytestCheckHook ];
  pythonImportsCheck = [ "secwatch" "secwatch.web.app" "secwatch.cli" ];

  meta = {
    description = "Self-hosted security monitoring for small fleets";
    homepage = "https://github.com/Tech-Maou/secwatch";
    license = {
      fullName = "PolyForm Noncommercial License 1.0.0";
      spdxId = "PolyForm-Noncommercial-1.0.0";
      url = "https://polyformproject.org/licenses/noncommercial/1.0.0/";
      free = false;
      redistributable = true;
    };
    mainProgram = "secwatch-web";
    platforms = lib.platforms.linux;
  };
}
