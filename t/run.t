#use Test::More tests => 1;
use Test::More qw(no_plan);
use JSON;

my @WARNINGS_FOUND;
BEGIN {
    $SIG{__WARN__} = sub { diag( "WARN: ", join( '', @_ ) ); push @WARNINGS_FOUND, @_ };
}

BEGIN { use_ok 'WWW::REST::Apid'};

use LWP;
use LWP::UserAgent;
use HTTP::Status;
use POSIX qw(:sys_wait_h SIGKILL SIGINT);

my $port = $ENV{HSB_TEST_PORT} || 8888;
my $host = $ENV{HSB_TEST_HOST} || '127.0.0.1';

diag( '' );
diag( '' );
diag( "Using port: $port and host: $host for test server.");
diag( 'If these are not suitable settings on your machine, set the environment' );
diag( 'variables HSB_TEST_PORT and HSB_TEST_HOST to something suitable.');
diag( '' );

our ($serverpid, $ua);

our %map = (
	    '/t/0' => {
		       handler => sub {
			 return { n => 1 };
		       },
		       post => 0,
		       expect => { n => 1 },
		       code => 200
		      }
);
our $json = JSON->new->allow_nonref;

sub setupserver {
  my $server;

  ok(
     $server = WWW::REST::Apid->new(host => $host, port => $port, foreground => 1),
     "started server"
    );

  isa_ok( $server, 'WWW::REST::Apid');

  foreach my $path (sort keys %map) {
    diag("Mapping $path");
    $server->mapuri(path => $path, %{$map{$path}});
  }

  if (!($serverpid = fork())) {
    diag('Starting server');
    $server->run;
    exit(0);
  }
}


sub testuri {
  my ($path, $post, $expect, $code) = @_;

  my $url = "http://$host:$port$path";

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new(GET => $url);

  my ($res, $data);

  ok($res = $ua->request($req), "$path (LWP request worked)" );

  cmp_ok($res->code, '==', $code, "$path (result code as expected).");
  
  ok( $data = $json->decode($res->content) );

  is_deeply($data, $expect, "$path (content matched).");
}




&setupserver();

foreach my $path (sort keys %map) {
  &testuri($path, $map{$path}->{post}, $map{$path}->{expect}, $map{$path}->{code});
}


END {
  kill(SIGINT, $serverpid);
}
