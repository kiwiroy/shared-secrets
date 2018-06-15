#!/usr/bin/env perl
package Mojo::File::Role::Expand;
use Mojo::Base -role;
use File::Path::Expand ();
around 'new' => sub {
  my $orig = shift;
  return $orig->(@_)->expand;
};
sub expand {
  my $self = shift;
  return Mojo::File->new(File::Path::Expand::expand_filename($$self));
}
1;
package Mojo::File::Expanded;
use Mojo::Base 'Mojo::File';
use Role::Tiny::With;
with 'Mojo::File::Role::Expand';

package main;
use Cwd ();
use Mojo::Base -base;
use Mojo::Collection 'c';
use Mojo::Exception;
use Mojo::Log;
use Mojo::Util qw{b64_encode quote};
use Applify;
use Archive::Tar;
use Crypt::CBC;
use Crypt::PK::RSA;
use Data::Entropy::Algorithms qw{rand_bits};
use IO::String;
use PerlIO::gzip;

extends 'Mojo::Base';

documentation $0;

has app_result => 0;

has cipher => sub {
  my $self = shift;
  return Crypt::CBC->new(
    -cipher => 'Cipher::AES',
    -key    => $self->encrypt_sym_key_decrypt,
    );
};

sub decrypt_data { shift->cipher->decrypt(shift); }

has decrypt_sym_key => sub {
  my $self = shift;
  return (split /\n/, $self->rsa->decrypt($self->symmetric->slurp, 'v1.5', 'rsautl'))[0];
};

sub encrypt_data { shift->cipher->encrypt(shift); }

has encrypt_sym_key_decrypt => sub {
  my $self = shift;
  return $self->decrypt_sym_key if -e $self->symmetric;
  my $rsa = Crypt::PK::RSA->new($self->public_key);
  $self->symmetric->spurt($rsa->encrypt(b64_encode(rand_bits(32 * 8)), 'v1.5', 'rsautl'));
  return $self->decrypt_sym_key;
};

has log => sub { Mojo::Log->new(level => 'info'); };

has public_key => sub {
  my $self = shift;
  return $self->private_key->sibling($self->private_key->basename . '.pub');
};

has rsa => sub {
  my $self = shift;
  my $priv_key = $self->private_key;
  my $password = $self->rsa_password;
  Mojo::Exception->throw('private key does not exist: ' . quote($priv_key) . "\n")
    if ! -e $priv_key;
  return Crypt::PK::RSA->new($priv_key) unless $password;
  return Crypt::PK::RSA->new($priv_key, $password);
};

has symmetric => sub {
  my $self = shift;
  return $self->symmetric_file if $self->can('symmetric_file');
  return $self->vault_file->sibling('symmetric.key.rsa')
    if $self->can('vault_file');
  Mojo::Exception->throw('unexpected state');
};

option file => private_key     => 'path to private key file',
  isa => 'Mojo::File::Expanded', required => 1,
  default => "~/.ssh/shared-secrets.pem";
option file => rsa_password    => 'password for private key';

subcommand create_keys => 'create keys to use', sub {};

subcommand decryptd => 'decrypt a directory', sub {
  option file => vault_file => 'vault file',
    isa => 'Mojo::File::Expanded', required => 1;
  option file => target_directory => 'target directory',
    isa => 'Mojo::File::Expanded', required => 1;
};

subcommand encryptd => 'encrypt a directory', sub {
  option file => vault_file => 'vault file',
    isa => 'Mojo::File::Expanded', required => 1;
  option file => target_directory => 'target directory',
    isa => 'Mojo::File::Expanded', required => 1;
};

subcommand decryptp => 'decrypt plain text',  sub {
  option file => input => 'input file',
    isa => 'Mojo::File::Expanded', required => 1;
  option file => symmetric_file => 'symmetric file to use',
    isa => 'Mojo::File::Expanded', required => 1;
};

subcommand encryptp => 'encrypt plain text',  sub {
  option file => input => 'input file',
    isa => 'Mojo::File::Expanded', required => 1;
  option file => symmetric_file => 'symmetric file to use',
    isa => 'Mojo::File::Expanded', required => 1;
};

sub command_create_keys {
  my $self = shift;
  my $pk = Crypt::PK::RSA->new();
  $pk->generate_key(256, 65537);

  my $private_pem = $pk->export_key_pem('private');
  $private_pem    = $pk->export_key_pem('private', $self->rsa_password)
    if $self->rsa_password;
  my $public_pem = $pk->export_key_pem('public');

  if (-e $self->private_key) {
    $self->log->warn("STOP private key already exists at " . quote $self->private_key);
  } else {
    $self->private_key->dirname->make_path;
    $self->private_key->spurt($private_pem);
    $self->log->info("Wrote private key to " . quote $self->private_key);
    $self->public_key->spurt($public_pem);
    $self->log->info("Wrote public key to " . quote $self->public_key);
  }

  return $self->app_result;
}

sub command_decryptd {
  my ($self, $buffer) = (shift, '');
  my $final_vault     = $self->vault_file;
  my $encrypted_vault = $final_vault->sibling('encrypted_keys.tar.gz');
  my $symmetric_file  = $final_vault->sibling('symmetric.key.rsa');
  my $vault_dir       = $final_vault->dirname;

  ## untar this into same directory
  my $tar = Archive::Tar->new($final_vault);
  $tar->extract_file($encrypted_vault->basename, $encrypted_vault);
  $tar->extract_file($symmetric_file->basename, $symmetric_file);

  my $gzipfh  = $encrypted_vault->open('<:gzip');
  my $content = do { local $/; <$gzipfh>; };
  my $io      = IO::String->new($self->decrypt_data($content));

  my $cwd = Cwd::getcwd();
  $tar = Archive::Tar->new($io);
  c($tar->list_files())
    ->tap(sub { chdir $self->target_directory->to_abs->tap(sub { $_->make_path }) })
    ->map(sub { $tar->extract($_); })
    ->tap(sub { chdir $cwd; });

  return $self->app_result;
}

sub command_decryptp {
  my $self = shift;
  say $self->decrypt_data($self->input->slurp);
  return $self->app_result;
}

sub command_encryptd {
  my ($self, $buffer) = (shift, '');
  my $final_vault     = $self->vault_file;
  my $encrypted_vault = $final_vault->sibling('encrypted_keys.tar.gz');
  my $symmetric_file  = $final_vault->sibling('symmetric.key.rsa');
  my $vault_dir       = $final_vault->dirname->tap(sub { $_->make_path });

  ## tar up the directory.
  my $tar = Archive::Tar->new();
  my $cwd = Cwd::getcwd();
  $self->target_directory
    ->to_abs
    ->tap(sub { chdir $_; })
    ->list_tree
    ->map(sub { $tar->add_files($_->to_rel); })
    ->tap(sub { chdir $cwd; });
  $tar->write(IO::String->new($buffer));

  ## encrypt the tar stream and write to compressed file
  my $gzipfh = $encrypted_vault->open('>:gzip');
  print $gzipfh $self->encrypt_data($buffer);
  $gzipfh->close;

  ## tar up the two files into final vault
  chdir $vault_dir->to_abs;
  $tar = Archive::Tar->new();
  $tar->add_files(
    $encrypted_vault->basename,
    $symmetric_file->basename
    );
  chdir $cwd;
  $tar->write($final_vault, 9);

  ## clean up these
  unlink($encrypted_vault, $symmetric_file);

  return $self->app_result;
}

sub command_encryptp {
  my $self = shift;
  say $self->encrypt_data($self->input->slurp);
  return $self->app_result;
}

app {
  my $self = shift;

  $self->_script->print_help;

  return $self->app_result;
};
