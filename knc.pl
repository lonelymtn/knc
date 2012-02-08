#!/usr/bin/env perl
# Time-stamp: <2012-02-08 12:55:03 (ryanc)>
#
# Author: Ryan Corder <ryanc@greengrey.org>
# Description: knc.pl - Eventual OpenBSD netcat clone with Kerberos support

use warnings;
use strict;

our $VERSION = '0.001';

use AnyEvent;
use AnyEvent::Handle;
use Authen::Krb5 qw(KRB5_NT_SRV_HST AP_OPTS_MUTUAL_REQUIRED);
use English qw(-no_match_vars);
use Getopt::Std;
use IO::Socket;

=head1 NAME

knc.pl - Eventual OpenBSD netcat clone with Kerberos support.

=head1 VERSION

This README refers to knc.pl version 0.001.

=head1 SYNOPSIS

    Simple server:

        knc.pl -l 127.0.0.1 12345

    Simple client:

        knc.pl 127.0.0.1 12345

    Kerberized server:

        knc.pl -l -K -N example -T /opt/etc/krb5.keytab 127.0.0.1 12345

    Kerberized client:

        kinit -f (You will need a TGT from your KDC first)
        knc.pl -K -N example 127.0.0.1 12345
=cut

$Getopt::Std::STANDARD_HELP_VERSION = 'true';

my %opts;
getopts( 'CkKN:lT:v', \%opts );

die HELP_MESSAGE() if ( !( $ARGV[0] && $ARGV[1] ) );
die HELP_MESSAGE() if ( !( $opts{'l'} && $opts{'k'} ) );

my $host   = $ARGV[0];             # IO::Socket::INET does host/ip validaiton
my $port   = $ARGV[1];             # IO::Socket::INET does port validation
my $ready  = AnyEvent->condvar;    # Set up our "main loop"
my $socket = create_socket();      # Socket needed before Kerberos can setup

# If we're doing Kerberos, go ahead and authenticate now
if ( $opts{'K'} ) {
    Authen::Krb5::init_context();

    my $krb5_service = $opts{'N'} // 'example';
    my $krb5_keytab  = $opts{'T'} // '/etc/krb5.keytab';
    my $krb5_ac      = Authen::Krb5::AuthContext->new();
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
    if ( $opts{'K'} ) {
        Authen::Krb5::free_context()
            or warn "KRB5 free context fail: $OS_ERROR\n";
    }

    if ($socket) {
        shutdown $socket, 2 or warn "Shutdown socket fail: $OS_ERROR\n";
        close $socket or warn "Close socket filehandle fail: $OS_ERROR\n";
    }

    if ($socket_handle) {
        $socket_handle->destroy
            or warn "Destroy socket handle fail: $OS_ERROR\n";
    }
    if ($stdin_handle) {
        $stdin_handle->destroy
            or warn "Destroy stdin handle fail: $OS_ERROR\n";
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

=head1 DIAGNOSTICS

Run the program with the '--help' swith for alist of all available options.

=cut

sub HELP_MESSAGE {
    print "\n"
        . "Usage: $0 [-CkKlv] [-N 'service name'] [-T /path/to/krb5.keytab]\n"
        . "       <hostname> <port>\n" . "\n"
        . "Examples:\n"
        . "    See the README or run this file through perldoc to see\n"
        . "    examples\n" . "\n"
        . "Syntax:\n"
        . "    -C    Send CRLF as line-ending.\n" . "\n"
        . "    -k    Forces $0 to stay listening for another connection after\n"
        . "          its current onneciton is completed.  It is an error to\n"
        . "          use this options without the -l option.\n" . "\n"
        . "    -K    Attempt to perform Kerberos authentication.\n" . "\n"
        . "    -l    Used to specify that $0 should listen for an incoming\n"
        . "          connextion rather than initiate a connection to a\n"
        . "          remote host.\n" . "\n"
        . "    -v    Have $0 give more verbose output.\n" . "\n"
        . "    -N <service name>\n"
        . "          Specifies which Kerberized service to attempt to\n"
        . "          authenticate to.  A matching Service Principal Name\n"
        . "          must exist in your REALM.  The default is 'example'.\n"
        . "\n"
        . "    -T <keytab>\n"
        . "          Specifies an alternative location for your keytab.\n"
        . "          The default is /etc/krb5.keytab.\n" . "\n";

    return 1;
}

=head1 AUTHOR

Ryan Corder, C<ryanc at greengrey.org>

=head1 KNOWN BUGS

Many of the features/switches from OpenBSD's netcat are not yet implemented.

SIGINT currently causes many things to either spew warnings or not close
altogether.

=head1 ACKNOWLEDGEMENTS

The OpenBSD project: L<http://openbsd.org>

Author(s) of the AnyEvent framework: L<https://metacpan.org/release/AnyEvent>

Author(s) of Authen::Krb5: L<https://metacpan.org/module/Authen::Krb5>

=head1 COPYRIGHT & LICENSE

Copyright 2012 Ryan corder, All Rights Reserved.

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
