#!/usr/bin/perl -Tw
#-
# Copyright (c) 2021 Dag-Erling Smørgrav
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

use utf8;
use strict;
use warnings;
use open qw(:locale);
use LWP;

our $TRACBASE = "https://openpam.org/wiki";

our %pages;

sub _p { "trac/$_[0].trac" }

sub mkparent {
    my ($path) = @_;

    return unless $path =~ s@/[^/]+$@@;
    return if -d $path;
    mkparent($path);
    mkdir($path) or die("$path: $!\n");
}

sub save {
    my ($path, $text) = @_;

    mkparent($path);
    open(my $fh, ">", "$path")
	or die("$path: $!\n");
     print($fh $text);
    close($fh);
}

sub tracpull {
    my ($tracbase, @queue) = @_;
    @queue = qw(WikiStart) unless @queue;
    my $ua = new LWP::UserAgent();
    $ua->agent("trac2gitea/0.20211020");
    while (@queue) {
	my $page = shift(@queue);
	next if $pages{$page};
	if (open(my $fh, "<", _p($page))) {
	    local $/;
	    $pages{$page} = <$fh>;
	    close($fh);
	} else {
	    my $req = new HTTP::Request(GET => "$tracbase/wiki/$page?format=txt");
	    my $res = $ua->request($req);
	    if (!$res->is_success) {
		warn(sprintf("%s: %s\n", $page, $res->status_line));
		next;
	    }
	    $pages{$page} = $res->decoded_content;
	    save(_p($page), $pages{$page});
	}
	foreach my $link ($pages{$page} =~ m@\[\[([\w/-]+)(?:\|[^|]+)?\]\]@g) {
	    next if $pages{$link};
	    push(@queue, $link);
	}
    }
}

sub convert {
    my ($page, $text) = @_;

    my $path = "$page.md";
    $path =~ s/\bWikiStart\b/Home/;
    $path =~ y@/@-@;
    $text =~ y/\r//d;
    $text =~ s/^= (.*) =$/# $1/gm;
    $text =~ s/^== (.*) ==$/## $1/gm;
    $text =~ s/^=== (.*) ===$/### $1/gm;
    $text .= "\n" unless $text =~ m/\n$/s;
    $text =~ s/'''/**/g;
    $text =~ s/\n/\r\n/gs;
    $text =~ s/\[([^\[\|\]\s]+) ([^\[\|\]\s][^\[\|\]]*)\]/[$2]($1)/gm;
    $text =~ s/\[\[([^\[\|\]]+)\|([^\[\|\]]+)\]\]/[$2]($1)/gm;
    $text =~ s/\| ([^\|]+) \|/| $1 |/gm;
    $text =~ s/\|= ([^\|]+) =\|/| **$1** |/gm;
    $text =~ s/\|\|/|/gm;
    $text =~ s/!([A-Z]\w+)/$1/gm;
    $text =~ s/\]\(([^\)\/]+)\/([^\)\/]+)\)/]($1-$2)/gm;
    save($path, $text);
}

MAIN:{
    tracpull("https://openpam.org");
    while (my ($page, $text) = each %pages) {
	convert($page, $text);
    }
}
