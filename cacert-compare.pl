#!/usr/bin/env perl

use v5.34;
use strict;
use experimental qw(signatures);
use Mojo::UserAgent;
use Mojo::URL;
use Mojo::DOM;
use Mojo::File;
use Smart::Comments;
use Digest::SHA qw(sha256_hex);
use Data::Dumper;
use Text::Diff;
use Crypt::X509;
use MIME::Base64;
use Encode;

my $ua = Mojo::UserAgent->new();

my $their_is_latest;
my $mine  = { url => $ARGV[0] ? $ARGV[0] : die "No \$mine URL" };
my $their = { url => $ARGV[1] ? $ARGV[1] : get_curl_cacert() };


foreach my $i ($mine, $their) {
  my $data = fetch($i->{url});
  $i->{data}   = $data;
  $i->{data_sha256} = sha256_hex($data);

  my ($filename) = $i->{url} =~ /\/([^\/]+?)$/;;

  $i->{filename} = $filename;

  my $norm = normalize($data);
  $i->{normalized}        = $norm;
  $i->{normalized_sha256} = sha256_hex($norm);
  $i->{certs} = [ decode_certs($data) ];
}


print "Compared [$mine->{filename}]($mine->{url}) against [$their->{filename}]($their->{url})";
if ($their_is_latest) {
  print ", the latest cacert.pem from curl.se, ";
}
print "to verify that the contain the same certs.";
say "";
say "";
if ($mine->{data_sha256} eq $their->{data_sha256}) {
  say "There were no differences, the files are identical";
} else {

  if ($mine->{normalized_sha256} eq $their->{normalized_sha256}) {
    say "No differences, apart from comments";
  } else {
    say "There are differences in content, please check";
  }

  say "```diff";
  say diff \$mine->{data}, \$their->{data},
    { FILENAME_A => $mine->{filename}, FILENAME_B => $their->{filename}};
  say "```";
  say "";
}


say "Compared at ".`TZ=UTC date`;
say "```";
foreach ($mine, $their) {
  say "$_->{data_sha256}  $_->{url}";
}
say "```";

foreach ($mine, $their) {
  my $num = $_->{certs}->@*;
  say "<details><summary>$num certificates in $_->{filename}</summary><b>url:</b> $_->{url}<br><b>sha256:</b> $_->{data_sha256}\n<ul>";
  foreach ($_->{certs}->@*) {
    say "<li>".encode("UTF-8", join(' ', $_->Subject->@*))."<br>$_->{_raw_sha256}</li>"
  }
  say "</ul></details>";
}


sub decode_certs ($data) {

  my $begin = "-----BEGIN CERTIFICATE-----\n";
  my $end   = "-----END CERTIFICATE-----\n";

  my @certs;
  open my $str_h, "<", \$data;
  my ($in, $buf);
  while (<$str_h>) {
    if ($_ eq $begin) {
      $in = 1;
    } elsif ($_ eq $end) {
      $in = undef;
      push @certs, decode_base64($buf);
      $buf = "";
    } elsif ($in) {
      $buf .= $_;
    }
  }
  close $str_h;

  my @decoded;
  foreach my $cert (@certs) {
    my $decoded = Crypt::X509->new(cert => $cert);
    $decoded->{_raw} = $cert;
    $decoded->{_raw_sha256} = sha256_hex($cert);
    if ($decoded->error) {
      die $decoded->error;
    }
    push @decoded, $decoded;
  }

  return @decoded;
}

sub fetch ($url) {
  my $res = $ua->get($url)->result;
  die "Failed getting $url: ".$res->code unless $res->is_success;
  my $body = $res->body;
  return $body;
}

sub normalize ($data) {
  $data =~ s/^##.+//mg;
  return $data;
}

sub get_curl_cacert {
  my $curl_page = Mojo::URL->new("https://curl.se/docs/caextract.html");
  my $curl_dom  = Mojo::DOM->new(fetch($curl_page));

  my ($first)   = $curl_dom->find("table tr td a[href]")->first->attr("href");
  die "Could not find latest cacert.pem om $curl_page" unless $first && $first =~ m|^/ca/cacert-[\d-]+?\.pem$|;
  my $ret = Mojo::URL->new($first)->base($curl_page)->to_abs . "";
  $their_is_latest++;
  return $ret;
}

# openssl crl2pkcs7 -nocrl -certfile bundled.crt | openssl pkcs7 -print_certs -noout
