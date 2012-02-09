#!/usr/bin/env perl
# Time-stamp: <2012-02-08 16:09:06 (ryanc)>
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

$Getopt::Std::STANDARD_HELP_VERSION = 'true';

my %opts;
getopts( 'CkKN:lT:v', \%opts );

# Exit early if certain required things are missing
die HELP_MESSAGE() if ( !( $ARGV[0] && $ARGV[1] ) );
die HELP_MESSAGE() if ( $opts{'k'} && ( !$opts{'l'} ) );

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

if ( $opts{'K'} ) {
    Authen::Krb5::free_context();
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
            shutdown $socket, 2;
            close $socket or AE::log error => "Shutdown socket failed.\n";
            undef $hdl;
            $ready->send;
        },
        on_error => sub {
            my ( $hdl, $fatal, $msg ) = @_;
            AE::log error => "$msg\n";
            undef $hdl;
            shutdown $socket, 2;
            close $socket or AE::log error => "Shutdown socket failed.\n";
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
            shutdown $socket, 2;
            close $socket or AE::log error => "Shutdown socket failed.\n";
            $ready->send;
        },
        on_error => sub {
            my ( $hdl, $fatal, $msg ) = @_;
            AE::log error => "$msg\n";
            $hdl->destroy;
            shutdown $socket, 2;
            close $socket or AE::log error => "Shutdown socket failed.\n";
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

sub HELP_MESSAGE {
    print << 'END_HELP';

Usage: knc.pl [-CkKlv] [-N 'service name'] [-T /path/to/krb5.keytab]
       <hostname> <port>

Examples:
    See the README or run this file through perldoc to see examples.

Syntax:
    -C    Send CRLF as line-ending.

    -k    Forces knc.pl to stay listening for another connection after its
          current conneciton is completed.  It is an error to use this
          options without the -l option.

    -K    Attempt to perform Kerberos authentication.

    -l    Used to specify that knc.pl should listen for an incoming connection
          rather than initiate a connection to a remote host.

    -v    Have knc.pl give more verbose output.

    -N <service name>
          Specifies which Kerberized service to attempt to authenticate to.  A
          matching Service Principal Name must exist in your REALM.  The
          default is 'example'

    -T <keytab>
          Specifies an alternative location for your keytab.  The default is
          /etc/krb5.keytab.

END_HELP

    return 1;
}

__END__

=head1 NAME

knc.pl - Eventual OpenBSD netcat clone with Kerberos support.

=head1 VERSION

This README refers to knc.pl version 0.001.

=head1 USAGE

Simple server:

    knc.pl -l 127.0.0.1 12345

Simple client:

    knc.pl 127.0.0.1 12345

Kerberized server:

    knc.pl -l -K -N example -T /opt/etc/krb5.keytab 127.0.0.1 12345

Kerberized client:

    kinit -f (You will need a TGT from your KDC first)
    knc.pl -K -N example 127.0.0.1 12345

=head1 REQUIRED ARGUMENTS

The Hostname/IP address and Port of the host you either want to connect to
or listen on are required.

=head1 OPTIONS

Run the program with the '--help' swith for alist of all available options.

=head1 DESCRIPTION

knc.pl aims to be a full clone of netcat that comes with OpenBSD.
Additionally, knc.pl supports Kerberos authentication in both client and
server modes.

As of this release, features are few.

For more information on OpenBSD's netcat, please see the current manual
at L<http://www.openbsd.org/cgi-bin/man.cgi?query=nc>

=head1 AUTHOR

Ryan Corder, C<ryanc at greengrey.org>

=head1 BUGS AND LIMITATIONS

Many of the features/switches from OpenBSD's netcat are not yet implemented.

SIGINT currently causes many things to either spew warnings or not close
altogether.

=head1 ACKNOWLEDGEMENTS

The OpenBSD project: L<http://www.openbsd.org>

Author(s) of the AnyEvent framework: L<https://metacpan.org/release/AnyEvent>

Author(s) of Authen::Krb5: L<https://metacpan.org/module/Authen::Krb5>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Ryan corder, All Rights Reserved.

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=head1 DIAGNOSTICS

=head1 CONFIGURATION

=head1 DEPENDENCIES

=head1 INCOMPATIBILITIES

=head1 EXIT STATUS

=cut
