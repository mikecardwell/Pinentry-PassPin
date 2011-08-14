#!/usr/bin/perl

##############################################################################
#                                                                            #
# Copyright 2011, Mike Cardwell - https://grepular.com/                      #
#                                                                            #
# This program is free software; you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License, or          #
# any later version.                                                         #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
# GNU General Public License for more details.                               #
#                                                                            #
# You should have received a copy of the GNU General Public License          #
# along with this program; if not, write to the Free Software                #
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA #
#                                                                            #
##############################################################################

use strict;
use warnings;
use IO::Select;
use IPC::Open2;

## Path to the gpg and pinentry executables

	my $gpg_path      = '/usr/bin/gpg';
	my $pinentry_path = '/usr/bin/pinentry';

## Path to the configuration

	my $config_path = "$ENV{HOME}/.pinentry-passpin";

## Parse args

	if( grep( /^(-h|--help)$/, @ARGV ) ){
		print << "END_HELP";
This script is a simple wrapper around your system pinentry application
and will pass along any arguments other than the following:

  --help or -h

    Display this information, and exit

  --add-key

    Will prompt you for your GnuPG passphrase, and the second wrapper
    passphrase, will encrypt your GnuPG passphrase with the wrapper
    passhprase, and then store it in ~/.pinentry-passpin

  --del-key

    Will prompt you for your wrapper passphrase, and then remove it
    from ~/.pinentry-passpin
END_HELP
		exit 0;
	}

## Read configuration

	my @keys;
	if( -f $config_path ){
		open my $in, '<', $config_path or die "Failed to open $config_path: $!\n";
		while( <$in> ){
			chomp( my $ciphertext = $_ );
			push @keys, $ciphertext;
		}
	}

## Add a new key?

	if( grep( $_ eq '--add-key', @ARGV ) ){
		add_key();
		exit 0;
	}

## Delete a key?

	if( grep( $_ eq '--del-key', @ARGV ) ){
		del_key();
		exit 0;
	}

## Spawn pinentry

	pinentry();

## Add new key

	sub add_key {

		## Ask the user for the real password

			print "Please enter the existing passphrase. The one you currently use to decrypt you key or access your smart card:\n> ";
			my $real_password = <STDIN>; $real_password =~ s/[\r\n]+//gsm;

		## Ask the user for the new password

			print "Please enter the new password which you would like to enter into pinentry instead of the real password:\n> ";
			my $fake_password = <STDIN>; $fake_password =~ s/[\r\n]+//gsm;

		## Make sure they're different

			die "Passphrases can not be the same\n" if $real_password eq $fake_password;

		## Check if that fake passphrase already links to another real passhprase
			{
				my $existing_password = retrieve_passphrase($fake_password);
				die "$fake_password is already in use in $config_path\n" if $existing_password ne $fake_password;
			}

		## Encrypt the real password using the fake password
		
			my $pid = open2( my $out, my $in, "$gpg_path --armor --symmetric --batch --passphrase-fd 0" );
			syswrite( $in, "$fake_password\n$real_password" );
			close $in;
			sysread( $out, my $ciphertext, 4096 );
			waitpid( $pid, 0 );

		## Remove extraneous data from the ciphertext

			$ciphertext =~ s/.*-----BEGIN PGP MESSAGE-----(.+)-----END PGP MESSAGE-----.*/$1/sm;
			$ciphertext =~ s/[\r\n]+//gsm;

		## Add config

			{
				my $exists = -f $config_path ? 1 : 0;
				open my $out, '>>', $config_path or die "Failed to open $config_path: $!\n";
				print $out "$ciphertext\n";
				close $out;
				unless( $exists ){
					chmod( 0600, $config_path ) or die "Failed to chmod $config_path to 0600\n";
				}
			}

		print "Key added to $config_path\n";
	}

## Delete a key from the configuration file

	sub del_key {

		print "Enter the passphrase configuration that you would like to remove from $config_path:\n> ";
		my $fake_pass = <STDIN>; $fake_pass =~ s/[\r\n]+//gsm;

		my $new_config = '';

		my $found = 0;
                foreach my $ciphertext ( @keys ){
                        my( $out, $in );
                        my $pid = open2( $out, $in, "$gpg_path -q --decrypt --batch --passphrase-fd 0 2>/dev/null" );
                        syswrite( $in, "$_\n" ) foreach(
                                $fake_pass,
                                '-----BEGIN PGP MESSAGE-----',
                                $ciphertext,
                                '-----END PGP MESSAGE-----',
                        );
                        close $in;
                        sysread( $out, my $buf, 4096 );
                        close $out;
                        waitpid( $pid, 0 );

			$found += length($buf);
                        $new_config .= "$ciphertext\n" unless length($buf);
                }

		if( $found ){
			open my $out, '>', $config_path or die "Failed to open $config_path: $!\n";
			print $out $new_config;
			close $out;
			print "Key deleted from $config_path\n";
		} else {
			print "Key not found in $config_path\n";
		}
        }

## Spawn pinentry, and forward communications between STDIN/STDOUT and the pinentry handle
## Intercept the response from GETPIN requests, and replace the entered password if possible

	sub pinentry {
		my( $pin_in, $pin_out );
		my $pid = open2( $pin_out, $pin_in, 'pinentry', @ARGV );

		my $sel = new IO::Select();
		$sel->add($_) foreach( \*STDIN, $pin_out, $pin_in );

		my $getpin = 0;
		while( my @ready = $sel->can_read() ){
			foreach my $sock ( @ready ){
				my( $bytes, $buf );
				{
					local $SIG{__WARN__} = sub {};
					$bytes = sysread( $sock, $buf, 4096 );
				};

				if( !defined $bytes || $bytes < 1 ){
					$sel->remove( $sock );
				} elsif( $sock == $pin_out ){
					if( $getpin ){
						$getpin = 0;
						if( $buf =~ /^D ([^\r\n]+)(.*)/s ){
							$buf = 'D '.retrieve_passphrase( $1 ).$2;
						}
					}
					syswrite( STDOUT, $buf );
				} else {
					$getpin = 1 if $buf =~ /^GETPIN$/i;
					syswrite( $pin_in, $buf );
				}
			}
		}
		waitpid( $pid, 0 );
	}

## Convert the passphrase if possible

	sub retrieve_passphrase {
		my $pass = shift;

		foreach my $ciphertext ( @keys ){
			my( $out, $in );
			my $pid = open2( $out, $in, "$gpg_path -q --decrypt --batch --passphrase-fd 0 2>/dev/null" );
			syswrite( $in, "$_\n" ) foreach(
				"$pass",
				'-----BEGIN PGP MESSAGE-----',
				$ciphertext,
				'-----END PGP MESSAGE-----',
			);
			close $in;
			sysread( $out, my $buf, 4096 );
			close $out;
			waitpid( $pid, 0 );

			if( length($buf) > 0 ){
				$buf =~ s/[\r\n]+$//gsm;
				return $buf;
			}
		}
		return $pass;
	}
