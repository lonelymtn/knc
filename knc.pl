#!/usr/bin/env perl
# Time-stamp: <2012-02-24 16:59:19 (ryanc)>
#
# Author: Ryan Corder <ryanc@greengrey.org>
# Description: knc.pl - Eventual OpenBSD netcat clone with Kerberos support

use warnings;
use strict;
use 5.010;

our $VERSION = '0.012';

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Log;
use Authen::Krb5
    qw( KRB5_NT_SRV_HST AP_OPTS_MUTUAL_REQUIRED ADDRTYPE_INET ADDRTYPE_IPPORT );
use English qw( -no_match_vars );
use Getopt::Long qw( :config posix_default bundling auto_version auto_help );
use IO::Socket;

my %opts = ();
GetOptions(
    \%opts,
    'verbose|v',     # Toggle verbosity
    'kerberos=s',    # Kerberos options & toggle
    'keytab=s',      # Path to KRB5 keytab
    'spn=s',         # KRB5 Service Principal Name
    'C',             # Send newline as \r\n
    'k',             # Stay listening after client disconnect
    'l',             # Listen for incoming connections
    'w:i',           # Socket && STDIN timeout
    'help|h' => sub { HELP_MESSAGE() },
);

$opts{'verbose'} && $AnyEvent::Log::FILTER->level('info');

# Checks for invalid option values and combinations
( !( $ARGV[0] && $ARGV[1] ) ) && AE::log fatal => HELP_MESSAGE();
( $opts{'k'} && ( !$opts{'l'} ) ) && AE::log fatal => HELP_MESSAGE();
( $opts{'w'} && ( $opts{'l'} ) )  && AE::log fatal => HELP_MESSAGE();
( $opts{'kerberos'} !~ /authonly|encrypt/xms )
    && AE::log fatal => HELP_MESSAGE();

my $host    = $ARGV[0];             # IO::Socket::INET does host/ip validaiton
my $port    = $ARGV[1];             # IO::Socket::INET does port validation
my $krb5_ac = q{none};              # We check later for a valid Auth Context
my $ready   = AnyEvent->condvar;    # Set up our "main loop"
my $socket  = create_socket();      # Socket needed before Kerberos can setup
my %timeout = (
    $socket => 0,                   # Socket has not timed out by default
    \*STDIN => 0                    # STDIN has not timed out by default
);

# Set up Kerberos context
$opts{'kerberos'} && Authen::Krb5::init_context();

# Server mode
if ( $opts{'l'} ) {

    # Keep socket open after client disconnect
    if ( $opts{'k'} ) {
        while ( my $listener = $socket->accept() ) {
            $ready = AnyEvent->condvar;

            $opts{'kerberos'} && setup_kerberos($listener);

            my $stdin_handle  = setup_ae_handle( $listener, \*STDOUT );
            my $socket_handle = setup_ae_handle( \*STDIN,   $listener );

            $ready->recv;
        }
    }

    # Close socket after client disconnect
    else {
        my $listener = $socket->accept();

        $opts{'kerberos'} && setup_kerberos($listener);

        my $stdin_handle  = setup_ae_handle( $listener, \*STDOUT );
        my $socket_handle = setup_ae_handle( \*STDIN,   $listener );

        $ready->recv;
    }
}

# Client mode
else {
    $opts{'kerberos'} && setup_kerberos($socket);

    my $stdin_handle  = setup_ae_handle( $socket, \*STDOUT );
    my $socket_handle = setup_ae_handle( \*STDIN, $socket );

    $ready->recv;
}

# Tear down Kerberos context
$opts{'kerberos'} && Authen::Krb5::free_context();

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

    my $krb5_service = $opts{'spn'}    // q{example};
    my $krb5_keytab  = $opts{'keytab'} // q{/etc/krb5.keytab};
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

    if ( $opts{'kerberos'} eq 'encrypt' ) {
        AE::log info => "All messages will be encrypted\n";
    }
    else {
        AE::log info => "Encryption disabled, authenticating only\n";
    }

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
        fh         => $fh_in,
        no_delay   => 1,
        timeout    => $opts{'l'} ? 0 : ( $opts{'w'} // 0 ),
        on_timeout => sub {
            my ($handle) = @_;
            handle_timeout( $fh_in, $handle );
        },
        on_eof => sub {
            my ($handle) = @_;
            AE::log info => "EOF reached on handle: $fh_in\n";
            $handle->destroy;
            $ready->send;
        },
        on_error => sub {
            my ( $handle, $fatal, $message ) = @_;
            if ($fatal) {
                $ready->croak($message);
            }
            else {
                AE::log error => "$OS_ERROR\n";
                $handle->destroy;
                $ready->send;
            }
        },
        on_read => sub {
            $timeout{$fh_in} = 0;

            if ( ref($fh_in) =~ /IO::Socket::INET/xms ) {
                if ( defined( $opts{'kerberos'} ) eq 'encrypt' ) {
                    shift->unshift_read(
                        line => qr{__END\015?\012}xms,
                        sub { kr5b_decode_msg( $fh_out, $_[1] ); }
                    );
                }
                else {
                    shift->unshift_read(
                        line => sub {
                            if ( $opts{'C'} ) {
                                syswrite $fh_out, "$_[1]\r\n";
                            }
                            else {
                                syswrite $fh_out, "$_[1]\n";
                            }
                        }
                    );
                }
            }
            else {
                shift->unshift_read(
                    line => sub {
                        my $line = $_[1];

                        if ( defined( $opts{'kerberos'} ) eq 'encrypt' ) {
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
    ) or AE::log fatal => "Could not create AE handle: $OS_ERROR\n";

    return $ae_handle;
}

sub kr5b_decode_msg {
    my ( $fh, $input ) = @_;

    if ( $krb5_ac eq 'none' ) {
        AE::log fatal => "Kerberos toggled but AC set to 'none'\n";
    }

    my $line = Authen::Krb5::rd_priv( $krb5_ac, $input );

    if ( !$line ) {
        my $krb5_status = Authen::Krb5::error();

        # NOT a failure, just an empty message
        if ( $krb5_status eq 'Success' ) {
            $line = $line // q{};
        }
        else {
            AE::log fatal => "Kerberos rd_priv error: $krb5_status\n";
        }
    }

    if ( $opts{'C'} ) {
        syswrite $fh, "$line\r\n";
    }
    else {
        syswrite $fh, "$line\n";
    }

    return 1;
}

sub handle_timeout {
    my ( $fh, $handle ) = @_;

    $timeout{$fh} = 1;

    foreach my $toggle ( keys %timeout ) {
        if ( $timeout{$toggle} == 0 ) {
            return 1;
        }
    }

    AE::log error => "Timeout reached on handle: $fh\n";
    $handle->destroy;
    $ready->send;

    return 1;
}

sub HELP_MESSAGE {
    my $help_message = << 'END_HELP';

Usage: knc.pl [-Cklv] [--kerberos [authonly|encrypt]]
       [--keytab /path/to/krb5.keytab] [--spn 'service name'] [-w timeout]
       <hostname> <port>

Examples:
    See the README or run this file through perldoc to see examples.

Syntax:
    -C    Send CRLF as line-ending.

    -k    Forces knc.pl to stay listening for another connection after the
          current conneciton is completed.  It is an error to use this
          options without the -l option.

    --kerberos [authonly|encrypt]
          When set to 'authonly', attempt to perform Kerberos authentication.
          When set to 'encrypt', also attempt to encrypt the messages between
          the cleint and the server.  A setting of 'encrypt' implies
          'authonly'.

    --keytab <keytab>
          Specifies an alternative location for your keytab.  The default is
          /etc/krb5.keytab.

    -l    Used to specify that knc.pl should listen for an incoming connection
          rather than initiate a connection to a remote host.

    --spn <service name>
          Specifies which Kerberized service to attempt to authenticate to.  A
          matching Service Principal Name must exist in your REALM.  The
          default is 'example'

    -v    Have knc.pl give more verbose output.

    -w timeout
          If a connection and stdin are idle for more than timeout seconds,
          then the connection is silently closed.  The -w flag has no effect
          on the -l option, i.e. nc will listen forever for a connection,
          with or without the -w flag.  The default is no timeout.

END_HELP

    print {*STDERR} $help_message
        or AE::log fatal => "Printing help to STDERR failed: $OS_ERROR.\n";

    exit 1;
}

__END__

=head1 NAME

knc.pl - Eventual OpenBSD netcat clone with Kerberos support.

=head1 VERSION

This README refers to knc.pl version 0.012.

=head1 USAGE

Simple server:

    knc.pl -l 127.0.0.1 12345

Simple client:

    knc.pl 127.0.0.1 12345

Kerberized server:

    knc.pl --kerberos encrypt --spn example -l 127.0.0.1 12345

Kerberized client:

    kinit -f (You will need a TGT from your KDC first)
    knc.pl --kerberos encrypt --spn example 127.0.0.1 12345

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

Timeouts (-w) are done via the AnyEvent handles since IO::Socket::INET doesn't
seem to implement them even though it has the option to specify it.  Besides,
nc (the real one) only times out if both the connection and STDIN reach the
timeout value...so using the handles makes sense.

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

0 for success, 1 for failure.

=cut
