#!/usr/bin/env perl
# Time-stamp: <2012-02-08 09:38:02 (ryanc)>
#
# Author: Ryan Corder <ryanc@greengrey.org>
# Description: knc.pl - Kerberized netcat

use warnings;
use strict;

use AnyEvent;
use AnyEvent::Handle;
use Authen::Krb5 qw(KRB5_NT_SRV_HST AP_OPTS_MUTUAL_REQUIRED);
use English qw(-no_match_vars);
use Getopt::Std;
use IO::Socket;

our $VERSION = '0.001';

my %opts;
getopts( 'CkKN:lTvw:', \%opts );

#die usage() unless ($opts);

my $host   = $ARGV[0];             # IO::Socket::INET does host/ip validaiton
my $port   = $ARGV[1];             # IO::Socket::INET does port validation
my $ready  = AnyEvent->condvar;    # Set up our "main loop"
my $socket = create_socket();      # Socket needed before Kerberos can setup

# If we're doing Kerberos, go ahead and authenticate now
if ( $opts{'K'} ) {
    Authen::Krb5::init_context();

    my $krb5_service = $opts{'N'} // 'example';
    my $krb5_keytab  = $opts{'T'} // '/home/ryanc/sys/etc/krb5.keytab';
    my $krb5_ac  = Authen::Krb5::AuthContext->new();
    my $krb5_spn = Authen::Krb5::sname_to_principal( $host, $krb5_service,
        KRB5_NT_SRV_HST );

    # Server context
    if ( $opts{'l'} ) {
        my $krb5_ktr = Authen::Krb5::kt_resolve("FILE:$krb5_keytab");
        my $krb5_recv =
            Authen::Krb5::recvauth( $krb5_ac, $socket, 'V1', $krb5_spn,
            $krb5_ktr );

        if ($krb5_recv) {
            if ( $opts{'v'} ) {
                print 'Received kerberos authentication info from '
                    . $krb5_recv->enc_part2->client->data . "\n";
            }
        }
        else {
            die 'recvauth error: ' . Authen::Krb5::error() . "\n";
        }
    }

    # Client context
    else {
        my $krb5_cc     = Authen::Krb5::cc_default();
        my $krb5_client = Authen::Krb5::parse_name( $ENV{'USER'} );
        my $krb5_send =
            Authen::Krb5::sendauth( $krb5_ac, $socket, 'V1', $krb5_client,
            $krb5_spn, AP_OPTS_MUTUAL_REQUIRED, 'knc', undef, $krb5_cc );

        if ($krb5_send) {
            if ( $opts{'v'} ) {
                print "Sent kerberos authentication info\n";
            }
        }
        else {
            die 'sendauth error: ' . Authen::Krb5::error() . "\n";
        }
    }
}

# Set up our AnyEvent handles for STDIN and the socket
my $stdin_handle  = setup_stdin_handle();
my $socket_handle = setup_socket_handle();

# "Main Loop"
$ready->recv;

exit 0;

# Clean up after we finish
END {
    shutdown $socket, 2 or warn "Shutdown socket fail: $OS_ERROR\n";
    close $socket or warn "Close socket filehandle fail: $OS_ERROR\n";
    $socket_handle->destroy or warn "Destroy socket handle fail: $OS_ERROR\n";
    $stdin_handle->destroy  or warn "Destroy stdin handle fail: $OS_ERROR\n";

    if ( $opts{'K'} ) {
        Authen::Krb5::free_context()
            or warn "KRB5 free context fail: $OS_ERROR\n";
    }
}

##
## Subroutines
##
sub create_socket {
    my $lsocket;

    if ( $opts{'l'} ) {
        my $listener = IO::Socket::INET->new(
            LocalAddr => $host,
            LocalPort => $port,
            Listen    => 1,
            ReuseAddr => $opts{'k'} ? 1 : 0,
            Proto     => 'tcp',
        ) or die $EVAL_ERROR, "\n";
        $lsocket = $listener->accept();
    }
    else {
        $lsocket = IO::Socket::INET->new(
            PeerAddr  => $host,
            PeerPort  => $port,
            ReuseAddr => $opts{'k'} ? 1 : 0,
            Proto     => 'tcp',
        ) or die $EVAL_ERROR, "\n";
    }

    return $lsocket;
}

sub setup_socket_handle {
    my $l_socket_handle = AnyEvent::Handle->new(
        fh       => $socket,
        no_delay => 1,
        on_eof   => sub {
            my ($hdl) = @_;
            undef $hdl;
            $ready->send;
        },
        on_error => sub {
            my ( $hdl, $fatal, $msg ) = @_;
            AE::log error => "$msg\n";
            undef $hdl;
            $ready->send;
        },
        on_read => sub {
            shift->unshift_read(
                line => sub {
                    if ( $opts{'C'} ) {
                        syswrite STDOUT, "$_[1]\r\n";
                    }
                    else {
                        syswrite STDOUT, "$_[1]\n";
                    }
                }
            );
        }
    );

    return $l_socket_handle;
}

sub setup_stdin_handle {
    my $l_stdin_handle = AnyEvent::Handle->new(
        fh       => \*STDIN,
        no_delay => 1,
        on_eof   => sub {
            my ($hdl) = @_;
            $hdl->destroy;
            $ready->send;
        },
        on_error => sub {
            my ( $hdl, $fatal, $msg ) = @_;
            AE::log error => "$msg\n";
            $hdl->destroy;
            $ready->send;
        },
        on_read => sub {
            shift->unshift_read(
                line => sub {
                    if ( $opts{'C'} ) {
                        syswrite $socket, "$_[1]\r\n";
                    }
                    else {
                        syswrite $socket, "$_[1]\n";
                    }
                }
            );
        }
    );

    return $l_stdin_handle;
}

