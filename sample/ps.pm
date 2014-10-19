# -*-cperl-*-

sub dops {
  my $filter = shift;
  my %p;

  my @lines = split /\n/, `ps axuw`;
  my @names = split /\s\s*/, shift @lines;

  foreach my $line (@lines) {
    if ($filter) {
      next if ($line !~ /$filter/);
    }
    my @vals = split /\s\s*/, $line, scalar @names;
    my %v = map { $names[$_] => $vals[$_] } 0 .. $#vals;
    $p{$v{PID}} = \%v;
  }

  return \%p;
}

sub ps2a {
  my $filter = shift;
  my $ps = &dops($filter);
  my @out = map { $ps->{$_} } sort { $a <=> $b } keys %{$ps};
  return \@out;
}

our %pw = ( tom => 123 );

auth basic => 'pslist';

implement login => sub {
  my($user, $pass) = @_;
  if (!exists $pw{$user}) {
    return 0;
  }
  else {
    if ($pass ne $pw{$user}) {
      return 0;
    }
  }
  return 1;
};

request login;
get '/ps' => sub {
  return &ps2a();
};

request login;
request validate => { pid => 'number' };
get '/ps/detail' => sub {
  my $data = shift;
  my $p = &dops();
  if (exists $p->{$data->{pid}}) {
    my $d = `ps ewww $data->{pid}`;
    my (undef, undef, undef, undef, $env) = split /\s\s*/, $d, 5;
    $out = $p->{$data->{pid}};
    foreach my $e (split /\s\s*/, $env) {
      my($var, $val) = split /=/, $e;
      $out->{env}->{$var} = $val;
    }
    return $out;
  }
  else {
    return {};
  }
};

request login;
request validate => { expression => 'text' };
get '/ps/search' => sub {
  my $data = shift;
  return &ps2a($data->{expression});
};


get '/' => sub {
  $res->header('Content-type' => 'text/html; charset=UTF-8');
  open I, "<index.html" or die "Could not open index.html: $!\n";
  my $html = join '', <I>;
  close I;
  $res->add_content($html);
  return 0;
};


1;
