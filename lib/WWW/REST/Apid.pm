#!/usr/bin/perl

package WWW::REST::Apid;

$WWW::REST::Apid::VERSION = '0.05';

use strict;
use warnings;

use Carp::Heavy;
use Carp;

use HTTP::Daemon;
use HTTP::Daemon::SSL;
use HTTP::Status qw(:constants :is status_message);
use HTTP::Request::Params;
use URI::Escape;
use Data::Dumper;
use CGI::Cookie;
use MIME::Base64;
use JSON;
use Digest::SHA qw(sha256_base64);
use Crypt::Random qw( makerandom );
use Data::Validate::Struct;
use DB_File;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $req $res);
require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw($req $res);
@EXPORT_OK = qw($req $res);




sub new {
  my ($class, %param) = @_;
  my $type = ref( $class ) || $class;

  # default config
  my %settings = (
		  host        => 'localhost',
		  port        => 8080,
		  timeout     => 5,
		  reuseaddr   => 1,
		  sessionfile => '/tmp/apid.sessions',
		  sublogin    => sub { print "login not implemented\n"; return 0; },
		  log         => sub { return 0; },
		  authbasic   => 'WWW::REST::Apid',
		  authuri     => '',
		  foreground  => 0, # don't fork if true
		  );

  # internals
  my %intern = (
		map         => {},
		sessions    => undef, # initialized later
		server      => undef, # initialized later
	       );
  
  # override defaults
  foreach my $key (keys %param) {
    $settings{$key} = $param{$key}; 
  }

  my $self = \%settings;
  bless $self, $type;

  # interns
  foreach my $key (keys %intern) {
    $self->{$key} = $intern{$key};
  }

  $self->_init();

  return $self;
}


sub mapuri {
  my($self, %p) = @_;

  $self->{map}->{$p{path}} = {
			      auth  => $p{doauth},
			      sub   => $p{handler},
			      valid => $p{validate} ? 
			               Data::Validate::Struct->new($p{validate}) : 0,
			     };
}

sub authuri {
  my($self, $uri) = @_;
  $self->{authuri} = $uri;
}

sub run {
  my $self = shift;

  $self->{log}("listening on $self->{host}:$self->{port}");

  if (! $self->{foreground}) {
    $self->{_old_sig_pipe_handler} = $SIG{'PIPE'};
    $SIG{'PIPE'} = 'IGNORE';
    $SIG{CHLD} = 'IGNORE';
  }

  while (1) {
    my $conn = $self->{server}->accept or next;

    if (! $self->{foreground}) {
      next if fork;
    }

    $self->_loadsessions();
    my ($r_port, $r_iaddr) = Socket::unpack_sockaddr_in($conn->peername);
    my $ip = Socket::inet_ntoa($r_iaddr);

    while (my $req = $conn->get_request) {
      $req->{remote_ip} = $ip;
      $req->{remote_port} = $r_port;
      $req->{path_info} = $req->uri->path;

      my $res = HTTP::Response->new;
      $res->code(200);
      $res = $self->_process($req, $res); # makes them global

      $conn->send_response($res);

      $self->{log}(join(' ', ($res->{user}, $ip, $res->code, $req->method, $req->uri->path)));
    }
    $self->_dumpsessions();
    exit if(! $self->{foreground});
  }
  $self->{log}("apid ended");
}




sub _init {
  my $self = shift;

  # check if ssl mode requested
  if (exists $self->{sslcrt} && exists $self->{sslkey}) {
    my %ssl;
    foreach my $key (keys %{$self}) {
      if ($key =~ /^SSL/) {
	$ssl{$key} = $self->{$key};
      }
    }
    $self->{server} = HTTP::Daemon::SSL->new(
					     LocalPort     => $self->{port},
					     LocalHost     => $self->{host},
					     ReuseAddr     => $self->{reuseaddr},
					     Timeout       => $self->{timeout},
					     SSL_key_file  => $self->{sslkey},
					     SSL_cert_file => $self->{sslcrt},
					     %ssl
					    ) or croak "Cannot start listener: $!\n";
  }
  else {
    $self->{server} = HTTP::Daemon->new(
					LocalPort => $self->{port},
					LocalHost => $self->{host},
					ReuseAddr => $self->{reuseaddr},
					Timeout   => $self->{timeout},	
				       ) or croak "Cannot start listener: $!\n";
  }
}








sub _authheader {
  my $self = shift;
  $res->header('WWW-Authenticate' => 'Basic realm=' . $self->{authbasic});
  $res->code(HTTP_UNAUTHORIZED);
  $res->header('Content-type' => 'application/json; charset=UTF-8');
  $res->add_content("{ \"error\": \"please authenticate\" }");
  return 0;
}

sub _doauthredir {
  my $self = shift;
  ($req, $res) = @_;
  my $data;

  if ($req->content) {
    if ($req->content =~ /^\{/) {
      eval { $data = decode_json($req->content); };
    }
    else {
      # try decoding as query
      my $query = HTTP::Request::Params->new({ req => $req });
      $data = $query->params;
      delete $data->{keywords};
    }
  }

  if ($data) {
    if (exists $data->{user} && exists $data->{pass}) {
      if ($self->{sublogin}->($data->{user}, $data->{pass})) {
	$self->_dosession($data->{user});
	$res->header('Content-type' => 'application/json; charset=UTF-8');
	$res->add_content("{ \"info\": \"authenticated\" }");
	return 1;
      }
    }
  }

  $res->code(HTTP_UNAUTHORIZED);
  $res->header('Content-type' => 'application/json; charset=UTF-8');
  $res->add_content("{ \"error\": \"please authenticate\" }");

  return 1;
}


sub _authredir {
  my $self = shift;
  $res->{target_uri} = URI::http->new($self->{authuri});
  $res->code(302);
  return 0;
}


sub _doauth {
  my $self = shift;

  if ($req->header('Cookie')) {
    my $rawcookie = $req->header('Cookie');
    if ($rawcookie =~ /^Session=(.*)$/) {
      my $session = uri_unescape($1);
      if (exists $self->{ses}->{$session}) {
	# ok, session known, user already authenticated
	my ($user, $time) = split /,/, $self->{ses}->{$session};
	if (time - $time < 86400) {
	  # ok, cookie age within bounds
	  $res->{user} = $user;
	  return 1;
	}
      }
    }
  }

  # no session
  if ($self->{authbasic}) {
    return $self->_doauthbasic();
  }
  else {
    return $self->_authredir();
  }
}

sub _doauthbasic {
  # no session, basic auth
  my $self = shift;

  my $auth = $req->header('Authorization');
  if (! $auth) {
    return $self->_authheader();
  }
  else {
    my ($basic, $b64) = split /\s\s*/, $auth;
    my $clear = decode_base64($b64);
    my($user, $pass) = split /:/, $clear;
    if (! $self->{sublogin}->($user, $pass)) {
      return $self->_authheader();
    }
    else {
      $self->_dosession($user);
      $res->header('WWW-Authenticate' => 'Basic realm="apid"');
    }
  }
  return 1;
}

sub _dosession {
  my ($self, $user) = @_;

  my $session = sha256_base64(makerandom ( Size => 512, Strength => 1 ) );
  $self->{ses}->{$session} = $user . "," . time;
  my $cookie = CGI::Cookie->new(
				-name    => 'Session',
				-expires => '+1d',
				-value   => $session);
  $res->header('Set-Cookie' => $cookie);
}

sub _process {
  my $self = shift;
  ($req, $res) = @_;

  my $fail = 1;
  my $path = '';
  my $found = 0;
  my $jsonop = JSON->new->allow_nonref;

  if (! $req->{path_info}) {
    $req->{path_info} = '/';
  }

  foreach my $path (sort { length($b) <=> length($a) } keys %{$self->{map}}) {
    if ($path eq $req->{path_info}) {
      $found = 1;
      if ($self->{map}->{$path}->{auth}) {
	if (! $self->_doauth()) {
	  last; # auth requested, user unauthenticated, else continue
	}
      }
      my $remainder = $req->{path_info};
      $remainder =~ s/\Q$path\E//;
      $req->{path_info} = $remainder;
      my $go = $self->{map}->{$path}->{sub};
      my ($put, $hash);

      if ($req->content) {
	if ($req->content =~ /^\{/) {
	  eval { $put = decode_json($req->content); };
	  if ($@) {
	    $@ =~ s/ at $0 line.*//;
	    $@ = "JSON Parser Error: $@";
	    last;
	  }
	}
	else {
	  # try decoding as query
	  my $query = HTTP::Request::Params->new({ req => $req });
	  $put = $query->params;
	  delete $put->{keywords}; 
	}
      }
      else {
	# maybe there were cgi get params
	my $query = HTTP::Request::Params->new({ req => $req });
	$put = $query->params;
	delete $put->{keywords}; 
      }

      if ($self->{map}->{$path}->{valid}) {
	my $ok;
	eval { $ok = $self->{map}->{$path}->{valid}->validate($put); };
	if (! $ok || $@) {
	  $@ =  $self->{map}->{$path}->{valid}->errstr();
	  chomp $@;
	  $@ =~ s/ at .*$//;
	  last;
	}
      }

      eval { $hash = $go->($put); };

      if (!$@) {
	if ($hash) {
	  my $json = encode_json($hash);
	  $res->add_content("$json");
	}
	$fail = 0;
      }

      last;
    }
  }

  if (!$found) {
    $res->code(404);
  }
  else {
    if (! $res->header('Content-type')) {
      $res->header('Content-type' => 'application/json; charset=UTF-8');
    }

    if ($fail) {
      $res->code(403);
      $res->add_content("{ \"error\": \"$@ $!\" }");
    }
  }

  $res->{user} = $res->{user} ? $res->{user} : '-';

  return $res;
}


sub _dumpsessions {
  my $self = shift;
  untie %{$self->{ses}};
}

sub _loadsessions {
  my $self = shift;
  tie %{$self->{ses}}, 'DB_File', $self->{sessions}, O_CREAT|O_RDWR, 0600, $DB_HASH;
}





1;

