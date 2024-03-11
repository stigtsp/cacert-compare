{ pkgs ? import <nixpkgs> {} }:

with pkgs;

let perl' = perl.withPackages(p: with p; [
      Mojolicious
      IOSocketSSL
      TextDiff
      SmartComments
      CryptX509
    ]);
in mkShell {
  buildInputs = [
    perl'
  ];
}
