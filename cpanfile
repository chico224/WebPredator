requires 'perl', '5.10.0';
requires 'Log::Log4perl', '1.56';
requires 'YAML::XS', '0.79';
requires 'JSON', '4.02';
requires 'Getopt::Long::Descriptive', '0.102';
requires 'LWP::UserAgent', '6.54';
requires 'HTTP::Cookies', '6.17';
requires 'Term::ANSIColor', '4.06';
requires 'Term::ProgressBar', '2.21';
requires 'Text::CSV', '1.95';
requires 'Mojo::UserAgent', '9.54';
requires 'Parallel::ForkManager', '2.04';
requires 'Net::DNS', '1.32';
requires 'Net::SSLeay', '1.88';

on 'develop' => sub {
    requires 'Test::More', '1.302192';
    requires 'Test::Exception', '0.45';
    requires 'Test::Warn', '0.36';
};
