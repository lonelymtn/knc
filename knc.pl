#!/usr/bin/env perl
# Time-stamp: <2012-02-16 16:57:24 (ryanc)>
#
# Author: Ryan Corder <ryanc@greengrey.org>
# Description: knc.pl - Eventual OpenBSD netcat clone with Kerberos support

use warnings;
use strict;

our $VERSION = '0.010';

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Log;
use Authen::Krb5
    qw(KRB5_NT_SRV_HST AP_OPTS_MUTUAL_REQUIRED ADDRTYPE_INET ADDRTYPE_IPPORT);
use English qw(-no_match_vars);
use Getopt::Std;
use IO::Socket;

$Getopt::Std::STANDARD_HELP_VERSION = 'true';

my %opts;
getopts( 'CkKN:lT:v', \%opts );

$opts{'v'} && $AnyEvent::Log::FILTER->level('info');

# Exit early if certain required things are missing
( !( $ARGV[0] && $ARGV[1] ) ) && AE::log fatal => HELP_MESSAGE();
( $opts{'k'} && ( !$opts{'l'} ) ) && AE::log fatal => HELP_MESSAGE();

my $host    = $ARGV[0];             # IO::Socket::INET does host/ip validaiton
my $port    = $ARGV[1];             # IO::Socket::INET does port validation
my $ready   = AnyEvent->condvar;    # Set up our "main loop"
my $socket  = create_socket();      # Socket needed before Kerberos can setup
my $krb5_ac = q{none};              # We check later for a valid Auth Context

# Set up Kerberos context
$opts{'K'} && Authen::Krb5::init_context();

# Server mode
if ( $opts{'l'} ) {

    # Keep socket open after client disconnect
    if ( $opts{'k'} ) {
        while ( my $listener = $socket->accept() ) {
            $ready = AnyEvent->condvar;

            $opts{'K'} && setup_kerberos($listener);

            my $stdin_handle  = setup_ae_handle( $listener, \*STDOUT );
            my $socket_handle = setup_ae_handle( \*STDIN,   $listener );

            $ready->recv;
        }
    }

    # Close socket after client disconnect
    else {
        my $listener = $socket->accept();

        $opts{'K'} && setup_kerberos($listener);

        my $stdin_handle  = setup_ae_handle( $listener, \*STDOUT );
        my $socket_handle = setup_ae_handle( \*STDIN,   $listener );

        $ready->recv;
    }
}

# Client mode
else {
    $opts{'K'} && setup_kerberos($socket);

    my $stdin_handle  = setup_ae_handle( $socket, \*STDOUT );
    my $socket_handle = setup_ae_handle( \*STDIN, $socket );

    $ready->recv;
}

# Tear down Kerberos context
$opts{'K'} && Authen::Krb5::free_context();

exit;

##
## Subroutines
##
sub create_socket {
    my $l_socket;

    # Server mode
    if ( $opts{'l'} ) {
        $l_socket = IO::Socket::INET->new(
            LocalAddr => $host,
            LocalPort => $port,
            Listen    => SOMAXCONN,
            Proto     => 'tcp',
            ReuseAddr => 1,
        ) or AE::log fatal => "$EVAL_ERROR\n";
    }

    # Client mode
    else {
        $l_socket = IO::Socket::INET->new(
            PeerAddr => $host,
            PeerPort => $port,
            Proto    => 'tcp',
        ) or AE::log fatal => "$EVAL_ERROR\n";
    }

    return $l_socket;
}

sub setup_kerberos {
    my $krb5_socket = shift;

    my $krb5_service = $opts{'N'} // q{example};
    my $krb5_keytab  = $opts{'T'} // q{/etc/krb5.keytab};
    my $krb5_spn = Authen::Krb5::sname_to_principal( $host, $krb5_service,
        KRB5_NT_SRV_HST );

    $krb5_ac = Authen::Krb5::AuthContext->new();

    # Set local and remote addresses, using network byte order
    $krb5_ac->setaddrs(
        Authen::Krb5::Address->new( ADDRTYPE_INET, pack 'a4',
            $krb5_socket->sockaddr()
        ),
        Authen::Krb5::Address->new( ADDRTYPE_INET, pack 'a4',
            $krb5_socket->peeraddr()
        )
    );
    $krb5_ac->setports(
        Authen::Krb5::Address->new( ADDRTYPE_INET, pack 'n',
            $krb5_socket->sockport()
        ),
        Authen::Krb5::Address->new( ADDRTYPE_INET, pack 'n',
            $krb5_socket->peerport()
        )
    );

    # Server context
    if ( $opts{'l'} ) {
        my $krb5_ktr = Authen::Krb5::kt_resolve("FILE:$krb5_keytab");
        my $krb5_recv =
            Authen::Krb5::recvauth( $krb5_ac, $krb5_socket, 'V1', $krb5_spn,
            $krb5_ktr );

        if ($krb5_recv) {
            AE::log info => 'Received Kerberos authentication info from '
                . $krb5_recv->enc_part2->client->data . "\n";
        }
        else {
            AE::log fatal => 'recvauth error: '
                . Authen::Krb5::error() . "\n";
        }
    }

    # Client context
    else {
        my $krb5_cc     = Authen::Krb5::cc_default();
        my $krb5_client = Authen::Krb5::parse_name( $ENV{'USER'} );

        # create the replay cache
        my ( $l_addr, $r_addr ) = $krb5_ac->getaddrs();
        my $krb5_lap =
            Authen::Krb5::gen_portaddr( $l_addr, $krb5_socket->sockport() );
        my $krb5_rcn =
            Authen::Krb5::gen_replay_name( $krb5_lap,
            q{knc-} . $krb5_socket->sockport() . q{-} );
        my $krb5_rc = Authen::Krb5::get_server_rcache($krb5_rcn);

        AE::log info => "Kerberos replay cache ($krb5_rcn) created.\n";
        $krb5_ac->setrcache($krb5_rc);

        my $krb5_send = Authen::Krb5::sendauth(
            $krb5_ac,  $krb5_socket,
            'V1',      $krb5_client,
            $krb5_spn, AP_OPTS_MUTUAL_REQUIRED,
            'knc',     undef,
            $krb5_cc
        );

        if ($krb5_send) {
            AE::log info =>
                "Sent Kerberos authentication info for $ENV{'USER'}\n";
        }
        else {
            AE::log fatal => 'sendauth error: '
                . Authen::Krb5::error() . "\n";
        }
    }

    return 1;
}

sub setup_ae_handle {
    my ( $fh_in, $fh_out ) = @_;

    my $ae_handle = AnyEvent::Handle->new(
        fh       => $fh_in,
        no_delay => 1,
        on_eof   => sub {
            my ($handle) = @_;
            undef $handle;
            $ready->send;
        },
        on_error => sub {
            my ( $handle, $fatal, $message ) = @_;
            if ($fatal) {
                $ready->croak($message);
            }
            else {
                AE::log error => "$OS_ERROR\n";
                undef $handle;
                $ready->send;
            }
        },
        on_read => sub {
            if ( ref($fh_in) =~ /IO::Socket::INET/xms ) {
                if ( $opts{'K'} ) {
                    shift->unshift_read(
                        line => qr{__END\015?\012}xms,    # Custom EOL marker
                        sub {
                            if ( $krb5_ac eq 'none' ) {
                                AE::log fatal =>
                                    "Kerberos toggled but AC set to 'none'\n";
                            }

                            my $line =
                                Authen::Krb5::rd_priv( $krb5_ac, $_[1] );

                            if ( !$line ) {
                                my $krb5_status = Authen::Krb5::error();

                                # NOT a failure, just an empty message
                                if ( $krb5_status eq 'Success' ) {
                                    $line = $line // q{};
                                }
                                else {
                                    AE::log fatal =>
                                        "Kerberos rd_priv error: $krb5_status\n";
                                }
                            }

                            if ( $opts{'C'} ) {
                                syswrite $fh_out, "$line\r\n";
                            }
                            else {
                                syswrite $fh_out, "$line\n";
                            }
                        }
                    );
                }
                else {
                    shift->unshift_read(
                        line => sub {
                            my $line = $_[1];

                            if ( $opts{'C'} ) {
                                syswrite $fh_out, "$line\r\n";
                            }
                            else {
                                syswrite $fh_out, "$line\n";
                            }
                        }
                    );
                }
            }
            else {
                shift->unshift_read(
                    line => sub {
                        my $line = $_[1];

                        if ( $opts{'K'} ) {
                            if ( $krb5_ac eq 'none' ) {
                                AE::log fatal =>
                                    "Kerberos toggled but AC set to 'none'\n";
                            }

                            my $enc_line =
                                Authen::Krb5::mk_priv( $krb5_ac, $line );

                            if ($enc_line) {
                                $line = $enc_line . '__END';
                            }
                            else {
                                AE::log fatal => 'Kerberos mk_priv error: '
                                    . Authen::Krb5::error() . "\n";
                            }
                        }

                        if ( $opts{'C'} ) {
                            syswrite $fh_out, "$line\r\n";
                        }
                        else {
                            syswrite $fh_out, "$line\n";
                        }
                    }
                );
            }
        }
    ) or AE::log fatal => "Couldn't create AE handle: $OS_ERROR\n";

    return $ae_handle;
}

sub HELP_MESSAGE {
    my $help_message = << 'END_HELP';

Usage: knc.pl [-CkKlv] [-N 'service name'] [-T /path/to/krb5.keytab]
       <hostname> <port>

Examples:
    See the README or run this file through perldoc to see examples.

Syntax:
    -C    Send CRLF as line-ending.

    -k    Forces knc.pl to stay listening for another connection after its
          current conneciton is completed.  It is an error to use this
          options without the -l option.

    -K    Attempt to perform Kerberos authentication.  If successful, messages
          will be encrypted between the client and the server.

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

    print {*STDERR} $help_message
        or AE::log fatal => "Printing help to STDERR failed: $OS_ERROR.\n";

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

If the Server is in Kerberos mode, but the Client is not and the client
connects, the server does not immediately close the connection.

=head1 ACKNOWLEDGEMENTS

The OpenBSD project: L<http://www.openbsd.org>

Author(s) of the AnyEvent framework: L<https://metacpan.org/release/AnyEvent>

Author(s) of Authen::Krb5: L<https://metacpan.org/module/Authen::Krb5>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Ryan Corder, All Rights Reserved.

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=head1 DIAGNOSTICS

=head1 CONFIGURATION

=head1 DEPENDENCIES

=head1 INCOMPATIBILITIES

=head1 EXIT STATUS

=cut
