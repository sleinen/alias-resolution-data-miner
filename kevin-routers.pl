#!/usr/bin/perl -w
##
## Script to collect information requested by Kévin Vermeulen:
##
##     So we are performing alias resolution, which consists in
##     grouping IP addresses into routers.
##     It would be great if we could have routers and their associated
##     IPs, so we could test our algorithm on it.
##
##     And yes, you're right, our work is related to ICMP rate
##     limiting, so if you have any informations on the model/
##     configuration of the routers used for ICMP rate limiting, it
##     would also be great.
##
## We collect information about our routers using RANCID, and have a
## script that extracts the IP(v4 and v6) addresses of all interfaces
## and outputs them in DNS format for inclusion in our zone files.
##
## Author:       Simon Leinen  <simon.leinen@switch.ch>
## Date created: 2019-05-03

use strict;
use warnings;

my $disclose_icmp_rate_limits = 0;

my $rancid_root = '/var/lib/rancid/backbone';

my $d_getciscoaddr = $ENV{'HOME'}.'/perl/alias-resolution-data-miner/d.getciscoaddr';

die unless -d $rancid_root;
die unless -r $d_getciscoaddr;

my %routers;

sub parse_d_getciscoaddr($ ) {
    my ($d_getciscoaddr) = @_;
    my ($name);
    open ADDR, $d_getciscoaddr or die "Cannot open $d_getciscoaddr: $!";
    while (<ADDR>) {
	if (/^; (.*): automatically generated entry$/) {
	    $name = 'swi'.$1;
	    $routers{lc $name} = {'name' => $name};
	} elsif (/^(\S*)\s+(A|AAAA)\s+(\S+)(?:\s+;.*)?$/) {
	    my $router = $routers{lc $name};
	    push @{$router->{'addrs'}}, $3;
	    # warn "router $name has address $3\n";
	} elsif (/^(\S*)\s+(LOC|CNAME)\s+(.+)(?:\s+;.*)?$/) {
	} elsif (/^;$/) {
	} else {
	    warn "huh? $_";
	}
    }
    close ADDR or die "Error closing $d_getciscoaddr: $!";
}

sub parse_rancid() {
    my $router_db = $rancid_root.'/router.db';
    open ROUTER_DB, $router_db or die "Cannot open $router_db: $!";
    while (<ROUTER_DB>) {
	my ($name, $kind, $status) = /^(.*):(.*):(up|down)$/;
	die "Cannot grok routers.db line $_"
	    unless defined $name;
	$routers{lc $name}->{kind} = $kind;
	next if $status eq 'down';

	my $config = $rancid_root.'/configs/'.$name;
	my ($context0, $context1);
	open CONFIG, $config
	    or die "Cannot open config file $config: $!";
	while (<CONFIG>) {
	    chomp;
	    if (/^ipv6 icmp error-interval (\d+) (\d+)$/
		or /^ip icmp rate-limit unreachable (\d+)$/
		or /^icmp ipv[46] rate-limit unreachable (\d+)$/
		or /^platform rate-limit unicast ip icmp .*$/
		or /^ ipv[46] icmp unreachables disable$/
	        or /^no ip icmp rate-limit unreachable( DF)?$/) {
		if ($disclose_icmp_rate_limits) {
		    if (/^\S/) {
			push @{$routers{lc $name}->{config}}, $_;
		    } else {
			push @{$routers{lc $name}->{config}}, $context0, $_;
		    }
		}
	    } elsif (/icmp/) {
		next if /(permit|deny) +icmp/;
		next if /^platform ipv6 acl icmp optimize neighbor-discovery$/;
		next if /^mls rate-limit unicast ip icmp unreachable (acl-drop|no-route) \d+( \d+)? ?$/;
		warn "$name: Possibly ICMP rate-limiting-related configuration:\n$_";
	    } else {
		$context0 = $_ if /^\S/;
		$context1 = $_ if /^ \S/;
	    }
	}
	close CONFIG
	    or die "Error closing config file $config: $!";
	# printf "%-20s %-10s %s\n", $name, $kind, $status;
    }
    close ROUTER_DB or die "error closing $router_db: $!";
}

sub out_yaml () {
    my $qual = '';
    $qual .= '-wirl' if $disclose_icmp_rate_limits;
    open OUT, ">kevin$qual.yml"
	or die "Cannot create kevin.yml: $!";
    print OUT "---\n";
    foreach my $name (sort keys %routers) {
	my $router = $routers{$name};
	next unless $router->{name};
	print OUT $router->{name},":\n";
	print OUT "  kind: ",$router->{kind},"\n" if exists $router->{kind};
	if (@{$router->{addrs}}) {
	    print OUT "  addrs:\n";
	    foreach my $addr (@{$router->{addrs}}) {
		print OUT "  - $addr\n";
	    }
	}
	if (exists $router->{config} and @{$router->{config}}) {
	    print OUT "  config:\n";
	    foreach my $config (@{$router->{config}}) {
		print OUT "  - $config\n";
	    }
	}
    }
    close OUT or die "Error closing kevin.yml: $!";
}

parse_d_getciscoaddr($d_getciscoaddr);
parse_rancid();
out_yaml();

1;
