#!/usr/bin/perl 
##!/usr/bin/perl
#
# GPL HEADER START
#
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License version 2 for more details (a copy is included
# in the LICENSE file that accompanied this code).
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; If not, see http://www.gnu.org/licenses
#
#
# GPL HEADER END
#
# Copyright 2014 
#
# Author: Roman Grigoryev<r-grigoryev@yandex.ru>
#

=pod

=head1 NAME

Xperior

=head1 SYNOPSIS

    traffic_counter.pl < --cfg | --help > [ --period ]

=head1 DESCRIPTION

Traffic counter for ASUS DSL N10 router. 
Application setup traffic counter via iptables on router and poll 
values for calculating current values. Application connects
to router via telnet and keep session as long as possible.

=head1 OPTIONS

=over 2

=item --cfg

Path to yaml config file
    ---
    host: router address, e.g. 1.2.3.4
    user: root_login
    pass: root_password
    addresses:
      - ip #1 address for monitoring
      - ....
      - ip addres #N

=item --period
    
Timse [sec] how often pool and report stats. Optional.
Default is 15

=item --help

Print usage help


=cut


use strict;
use warnings;
use POSIX;
use Net::Telnet;
use File::Slurp;
use Getopt::Long;
use Pod::Usage;
use Carp;
use YAML qw "Bless LoadFile Load";
use Log::Log4perl qw(:easy);
Log::Log4perl->easy_init($DEBUG);
$| = 1;

my $period = 15;
my $cfgpath   = '';
my $helpflag;
my $manflag;
my $nopts;
$nopts = 1 unless ( $ARGV[0] );

GetOptions(
    "cfg:s"      => \$cfgpath,
    "period:s"    => \$period,
    "help!"      => \$helpflag,
    );

pod2usage( -verbose => 1 ) if ( ($helpflag) || ($nopts) );

pod2usage( -verbose => 2 ) if ($manflag);

if ( ( not defined $cfgpath ) || (  $cfgpath eq '' ) ) {
    print "No config file with YAML files set!\n";
    pod2usage(3);
    exit 1;
}

my $cfg = LoadFile($cfgpath) or 
    confess "Cannot load yaml file [$cfgpath] $!";
my $host = $cfg->{'host'};
my $user = $cfg->{'user'};
my $pass = $cfg->{'pass'};
DEBUG "Configuration loaded";

my @monitor_list = @{$cfg->{'addresses'}};
#(
#    '192.168.96.75',
#    '192.168.96.76',
#    '192.168.96.92',
#    '192.168.96.150',
#);

my $watchfile='/tmp/traffic.log';

my %in;
my %out;
my $starttime=0;
my $endtime=0;
my $difftime=0;
my $content='';

sub well_out {
    my $mode  = shift;
    my @lines = @_;
    my $found = 0;
    #DEBUG @lines;
    my $data     = \%in;
    my $ip_place = 8;
    if ( $mode eq 'out' ) {
        $ip_place = 7;
        $data = \%out;
    }
    DEBUG "mode [$mode]";
    foreach my $line (@lines) {
        if( $line =~ m/\d+\s+\d+/ ) {

            $found ++;
            my @columns = split( /\s+/, $line );
            my $ip      = $columns[$ip_place];
            my $traf    = $columns[2];
            #bad data
            if((not defined($ip)) or ($ip eq '0.0.0.0/0')){
                return 0;
            }
            #DEBUG "ip=$ip kb = " . ( $traf / 1000 );
            if ( defined($data->{$ip})) {
                my $trafdiff = $traf - $data->{$ip};
                my $t =  ceil( $trafdiff / ( 1000  * $difftime ) );
                DEBUG "$ip: $t kbit/sec";
                $content = $content. "mode=$mode\t$ip\t$t\n"
            }
            $data->{$ip} = $traf;
        }
    }
    return $found;
}

sub getTelnetConnection{
    my $router = new Net::Telnet(
        Timeout => 30,
        Prompt  => '/\#\ $/'
    );
    $router->errmode('return');
    $router->open($host);
    $router->login( $user, $pass );
    DEBUG "Connected";
    return $router;
}
my $router; 
while( 1==1){
    DEBUG "Check";
    undef %in;
    undef %out;
    $starttime=0;
    $endtime=0;
    #$router->close() if defined $router;
    
    $router = getTelnetConnection();

    #check iptables setup status
    # suppose that if no chain found we should re-setup all
    my @chain  = $router->cmd("iptables -L TRAFFIC_ACCT_IN");
    #DEBUG   @chain;
    if(defined $chain[0] and  $chain[0] =~ /ret=0/){
        DEBUG 'Setup chains';
        $router->cmd("iptables -N TRAFFIC_ACCT_IN");
        $router->cmd("iptables -N TRAFFIC_ACCT_OUT");
        $router->cmd("iptables -I logaccept -j TRAFFIC_ACCT_IN");
        $router->cmd("iptables -I logaccept -j TRAFFIC_ACCT_OUT");
    
        foreach my $node (@monitor_list){
            DEBUG "Setup rules for $node";
            $router->cmd("iptables -A TRAFFIC_ACCT_IN --dst  ".$node);
            $router->cmd("iptables -A TRAFFIC_ACCT_OUT --src ".$node);
        }
    }elsif( not defined $chain[0] ){
        DEBUG "No output received, restarting";
        sleep $period;
        next;
    }
    DEBUG "Setup done, monitring";
    my $i=0;
    while ( 1 == 1 ) {
        DEBUG 'Check at ['.time.']';
        $content='';
        my @in_lines  = $router->cmd("iptables -L TRAFFIC_ACCT_IN  -n -v -x");
        my @out_lines = $router->cmd("iptables -L TRAFFIC_ACCT_OUT  -n -v -x");
        $endtime = time();
        $difftime = $endtime - $starttime;
        $starttime=$endtime;  
        my $f1 = well_out( 'in',  @in_lines );
        my $f2 = well_out( 'out', @out_lines );
        if (($i > 0)and($f1 == 0 or $f2 == 0)){
            DEBUG 'Reset all';
            last;
        }
        write_file($watchfile,
            {err_mode => 'croak',atomic => 1},
            time()."\n$content");
          sleep $period;
          $i++;
    }
    sleep $period;
}

__END__

=head1 COPYRIGHT AND LICENSE

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 only,
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License version 2 for more details (a copy is included
in the LICENSE file that accompanied this code).

You should have received a copy of the GNU General Public License
version 2 along with this program; If not, see http://www.gnu.org/licenses



Copyright 2014  Roman Grigoryev

=head1 AUTHOR

Roman Grigoryev<r-grigoryev@yandex.ru>

=cut

