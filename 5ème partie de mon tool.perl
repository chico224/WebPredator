#!/usr/bin/perl -w

##
# WebPredator Web Scanner
# Next-generation web vulnerability scanner
# Features:
# - Modern web technology support (HTTP/2, WebSockets)
# - Comprehensive API security testing
# - Cloud-native application scanning
# - Advanced threat intelligence integration
# - Parallel scanning engine
# - Multiple report formats (HTML, JSON, SARIF)
##

use strict;
use warnings;
use feature 'say';
use Getopt::Long::Descriptive;
use Log::Log4perl qw(get_logger);
use YAML::XS qw(LoadFile);
use JSON qw(decode_json encode_json);
use HTTP::Request;
use HTTP::Response;
use HTTP::Cookies;
use Term::ANSIColor qw(:constants);
use Term::ProgressBar;
use Socket;
use IO::Socket;
use IO::Socket::SSL;
use Time::HiRes qw(gettimeofday tv_interval);
use POSIX qw(strftime);
use File::Basename;
use File::Path;
use MIME::Base64;
use List::Util qw(shuffle);
use Cwd 'abs_path';

# Initialisation du logging
BEGIN {
    Log::Log4perl->init(\<<'EOL');
log4perl.rootLogger=DEBUG, Screen, File

# Console avec couleurs
log4perl.appender.Screen=Log::Log4perl::Appender::Screen
log4perl.appender.Screen.layout=Log::Log4perl::Layout::PatternLayout
log4perl.appender.Screen.layout.ConversionPattern=%d{ISO8601} %p %m%n
log4perl.appender.Screen.Threshold=INFO

# Fichier JSON
log4perl.appender.File=Log::Log4perl::Appender::File
log4perl.appender.File.filename=webpredator.log
log4perl.appender.File.layout=Log::Log4perl::Layout::JSON
log4perl.appender.File.Threshold=DEBUG
EOL
}

# Configuration par défaut
our %DEFAULT_CONFIG = (
    'PLUGINDIR'    => 'plugins',
    'DBDIR'        => 'database',
    'TEMPLATEDIR'  => 'templates',
    'EXECDIR'      => 'exec',
    'REPORTDIR'    => 'reports',
    'USERAGENT'    => 'Mozilla/5.0 (compatible; WebPredator/4.2; +https://webpredator.io)',
    'MAX_WARNINGS' => 100,
    'MAX_ERRORS'   => 20,
    'TIMEOUT'      => 10,
    'SSL_OPTIONS'  => { SSL_version => 'TLSv1_3' },
    'THREADS'      => 5,
    'REPORT_FORMAT'=> 'json',
    'LOG_FORMAT'   => 'text',
    'NO_PROGRESS'  => 0,
    'DEBUG'       => 0,
    'AUTH'        => undef,
    'COOKIES'     => undef,
    'WEBHOOK'     => undef,
    'SELF_UPDATE' => 0,
);

# Modern dependencies
use Mojo::UserAgent;
use Parallel::ForkManager;
use Net::DNS;
use Net::SSLeay;

our $VERSION = "4.2.0";
our $RELEASE = "2024-06";

# Global configuration
our %CONFIG = (
    'PLUGINDIR'    => 'plugins',
    'DBDIR'        => 'database',
    'TEMPLATEDIR'  => 'templates',
    'EXECDIR'      => 'exec',
    'REPORTDIR'    => 'reports',
    'USERAGENT'    => 'Mozilla/5.0 (compatible; WebPredator/4.2; +https://webpredator.io)',
    'MAX_WARNINGS' => 100,
    'MAX_ERRORS'   => 20,
    'TIMEOUT'      => 10,
    'SSL_OPTIONS'  => { SSL_version => 'TLSv1_3' },
);

# Threat intelligence integration
our %THREAT_FEEDS = (
    'CVE'          => 'https://api.webpredator.io/v1/threats/cve',
    'OWASP'        => 'https://api.webpredator.io/v1/threats/owasp',
    'THREAT_FEED'  => 'https://api.webpredator.io/v1/threats/latest'
);

# Vulnerability checks database
our @SECURITY_CHECKS = (
    {
        id => 'API-001',
        description => 'Insecure API endpoint without authentication',
        severity => 'HIGH',
        match => qr/\"message\"\s*:\s*\"?unauthorized/i,
        remediation => 'Implement OAuth2 or JWT authentication'
    },
        severity => 'CRITICAL',
        remediation => 'Restrict cloud metadata endpoint access'
    },
    # Additional checks...
);

# Génération du rapport
sub generate_report {
    my ($self, $format) = @_;
    my $logger = get_logger();
    $format ||= $self->{config}{'REPORT_FORMAT'};

    if ($format eq 'csv') {
        require Text::CSV;
        my $csv = Text::CSV->new({ binary => 1, auto_diag => 1 });
        my $fh;
        if (open $fh, '>', $self->{config}{'REPORTDIR'} . '/report.csv') {
            $csv->print($fh, [qw(id description severity remediation)]);
            foreach my $vuln (@{$self->{results}}) {
                $csv->print($fh, [
                    $vuln->{id},
                    $vuln->{description},
                    $vuln->{severity},
                    $vuln->{remediation}
                ]);
            }
            close $fh;
            $logger->info("Report saved to report.csv");
        }
    } elsif ($format eq 'sarif') {
        my $report = {
            "\$schema" => "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            version => "2.1.0",
            runs => [{
                tool => {driver => {name => "WebPredator", version => $VERSION}},
                results => [
                    map {
                        {
                            ruleId => $_->{id},
                            level => "error",
                            message => {text => $_->{description}},
                            locations => [{
                                physicalLocation => {
                                    artifactLocation => {
                                        uri => $_->{target}
                                    }
                                }
                            }]
                        }
                    } @{$self->{results}}
                ]
            }]
        };
        
        if (open my $fh, '>', $self->{config}{'REPORTDIR'} . '/report.sarif') {
            print $fh encode_json($report);
            close $fh;
            $logger->info("Report saved to report.sarif");
        }
    } else {  # json par défaut
        if (open my $fh, '>', $self->{config}{'REPORTDIR'} . '/report.json') {
            print $fh encode_json({
                version => $VERSION,
                timestamp => strftime("%Y-%m-%d %H:%M:%S", localtime),
                vulnerabilities => $self->{results},
                summary => {
                    critical => scalar(grep { $_->{severity} eq 'CRITICAL' } @{$self->{results}}),
                    high => scalar(grep { $_->{severity} eq 'HIGH' } @{$self->{results}}),
                    medium => scalar(grep { $_->{severity} eq 'MEDIUM' } @{$self->{results}}),
                    low => scalar(grep { $_->{severity} eq 'LOW' } @{$self->{results}})
                }
            });
            close $fh;
            $logger->info("Report saved to report.json");
        }
    }

    # Envoi webhook si activé
    if ($self->{config}{'WEBHOOK'}) {
        my $ua = LWP::UserAgent->new;
        my $response = $ua->post(
            $self->{config}{'WEBHOOK'},
            Content => encode_json({
                version => $VERSION,
                target => $self->{config}{'host'},
                vulnerabilities => $self->{results}
            })
        );
        if ($response->is_success) {
            $logger->info("Report sent to webhook");
        } else {
            $logger->error("Webhook failed: " . $response->status_line);
        }
    }
}
        severity => 'CRITICAL',
        remediation => 'Restrict cloud metadata endpoint access'
    },
    # Additional checks...
);

# Main scanner class
package WebPredator;

sub new {
    my $class = shift;
    my %args = @_;
    
    my $self = {
        host => $args{host},
        port => $args{port} || 80,
        ssl  => $args{ssl} || 0,
        timeout => $args{timeout} || $CONFIG{'TIMEOUT'},
        plugins => [],
        results => [],
        config => \%CONFIG,
        threat_feeds => \%THREAT_FEEDS,
        security_checks => \@SECURITY_CHECKS,
        stats => {
            start_time => [gettimeofday],
            requests => 0,
            vulnerabilities => {
                critical => 0,
                high => 0,
                medium => 0,
                low => 0
            }
        }
    };
    
    bless $self, $class;
    
    # Détection passive du serveur et OS
    if (!$self->{config}{'NO_PASSIVE'}) {
        my $detect = $self->_detect_server_os($self->{config}{'host'});
        $self->{config}{'DETECTED_SERVER'} = $detect->{server};
        $self->{config}{'DETECTED_OS'} = $detect->{os};
        
        my $logger = get_logger();
        $logger->info("Detected server: " . $detect->{server});
        $logger->info("Detected OS: " . $detect->{os});
    }
    
    $self->_init();
    return $self;
}

sub _init {
    my $self = shift;
    
    # Initialize HTTP clients
    $self->{ua} = Mojo::UserAgent->new;
    $self->{ua}->transactor->name($CONFIG{'USERAGENT'});
    $self->{ua}->request_timeout($self->{timeout});
    
    $self->{lwp_ua} = LWP::UserAgent->new(
        agent => $CONFIG{'USERAGENT'},
        timeout => $self->{timeout},
        ssl_opts => $CONFIG{'SSL_OPTIONS'},
    );
    
    # Load components
    $self->_load_plugins();
    $self->_load_threat_intel();
    
    say "[*] WebPredator $VERSION initialized for target: " . $self->{host};
}

sub _load_plugins {
    my $self = shift;
    
    my $plugin_dir = $self->{config}{'PLUGINDIR'};
    opendir(my $dh, $plugin_dir) or die "Cannot open plugin directory: $!";
    
    while (my $file = readdir($dh)) {
        next unless $file =~ /\.pm$/;
        my $plugin = $file;
        $plugin =~ s/\.pm$//;
        
        require "$plugin_dir/$file";
        my $plugin_class = "WebPredator::Plugin::$plugin";
        
        push @{$self->{plugins}}, $plugin_class->new(
            scanner => $self,
            config => $self->{config}
        );
    }
    
    closedir $dh;
    say "[+] Loaded " . scalar(@{$self->{plugins}}) . " security plugins";
}

sub _load_threat_intel {
    my $self = shift;
    
    # Async threat intel loading
    $self->{ua}->get($THREAT_FEEDS{'THREAT_FEED'} => sub {
        my ($ua, $tx) = @_;
        if (my $res = $tx->success) {
            $self->{threat_data} = $res->json;
        }
    });
    
    # Additional threat intel loading...
}

# Core scanning methods
sub scan {
    my $self = shift;
    
    say "[*] Starting comprehensive scan against " . $self->{host};
    
    # Phased scanning approach
    $self->_discovery_phase();
    $self->_modern_web_scan();
    $self->_api_security_scan();
    $self->_cloud_security_scan();
    $self->_traditional_scan();
    
    $self->generate_report();
    
    my $elapsed = tv_interval($self->{stats}{start_time});
    say "[*] Scan completed in $elapsed seconds";
    say "[*] Found " . $self->{stats}{vulnerabilities}{critical} . " critical vulnerabilities";
}

sub _discovery_phase {
    my $self = shift;
    
    say "[*] Running discovery phase";
    
    $self->_dns_analysis();
    $self->_cloud_metadata_check();
    $self->_api_documentation_check();
    $self->_framework_detection();
}

sub _modern_web_scan {
    my $self = shift;
    
    say "[*] Scanning modern web vulnerabilities";
    
    $self->_websocket_security_check();
    $self->_http2_security_check();
    $self->_security_headers_check();
    $self->_frontend_vulnerabilities();
}

sub _api_security_scan {
    my $self = shift;
    
    say "[*] Testing API security";
    
    $self->_test_broken_object_auth();
    $self->_test_data_exposure();
    $self->_test_insecure_endpoints();
    $self->_test_graphql_vulnerabilities();
}

sub _cloud_security_scan {
    my $self = shift;
    
    say "[*] Scanning cloud-native vulnerabilities";
    
    $self->_check_cloud_storage();
    $self->_check_container_endpoints();
    $self->_check_serverless_functions();
}

sub _traditional_scan {
    my $self = shift;
    
    say "[*] Running traditional web vulnerability checks";
    
    foreach my $plugin (@{$self->{plugins}}) {
        $plugin->execute();
    }
}

# Reporting functionality
sub generate_report {
    my $self = shift;
    my %args = @_;
    
    my $format = $args{format} || 'html';
    my $output_file = $args{output} || "webpredator_scan_" . strftime("%Y%m%d-%H%M%S", localtime) . ".$format";
    
    say "[*] Generating $format report: $output_file";
    
    if ($format eq 'html') {
        $self->_generate_html_report($output_file);
    }
    elsif ($format eq 'json') {
        $self->_generate_json_report($output_file);
    }
    elsif ($format eq 'sarif') {
        $self->_generate_sarif_report($output_file);
    }
}

sub _generate_html_report {
    my ($self, $file) = @_;
    
    open(my $fh, '>', $file) or die "Cannot open report file: $!";
    
    print $fh <<"END_HTML";
<!DOCTYPE html>
<html>
<head>
    <title>WebPredator Security Report</title>
    <style>
        /* Modern report styling */
    </style>
</head>
<body>
    <h1>WebPredator Security Scan Report</h1>
    <div class="target-info">
        <p>Scanned: $self->{host}</p>
        <p>Completed: @{[strftime("%Y-%m-%d %H:%M:%S", localtime)]}</p>
    </div>
    
    <div class="vulnerability-summary">
        <!-- Vulnerability summary -->
    </div>
    
    <div class="detailed-findings">
        <!-- Detailed findings -->
    </div>
</body>
</html>
END_HTML

    close $fh;
}

# Security check implementations
sub _websocket_security_check {
    my $self = shift;
    
    my $url = ($self->{ssl} ? 'wss://' : 'ws://') . $self->{host} . ':' . $self->{port} . '/';
    
    eval {
        my $ws = $self->{ua}->websocket($url => sub {
            my ($ua, $tx) = @_;
            
            $tx->on(finish => sub {
                my ($tx, $code, $reason) = @_;
                # Analyze WebSocket connection
            });
            
            $tx->on(message => sub {
                my ($tx, $msg) = @_;
                # Check for sensitive data exposure
            });
        });
        
        Mojo::IOLoop->start unless Mojo::IOLoop->is_running;
    };
}

sub _test_broken_object_auth {
    my $self = shift;
    
    my $test_endpoints = [
        '/api/users/123',
        '/api/orders/456',
        '/api/admin/settings'
    ];
    
    foreach my $endpoint (@$test_endpoints) {
        my $url = ($self->{ssl} ? 'https://' : 'http://') . $self->{host} . ':' . $self->{port} . $endpoint;
        
        my $res = $self->{ua}->get($url)->result;
        
        if ($res->is_success && $res->body !~ /not authorized|forbidden/i) {
            $self->_log_vulnerability(
                id => 'API-002',
                description => "Broken Object Level Authorization at $endpoint",
                severity => 'HIGH',
                request => $url,
                response => $res->body
            );
        }
    }
}

# Utility methods
sub _log_vulnerability {
    my ($self, %args) = @_;
    
    my $vuln = {
        id => $args{id} || 'CUSTOM-001',
        description => $args{description},
        severity => $args{severity} || 'MEDIUM',
        request => $args{request},
        response => $args{response},
        timestamp => strftime("%Y-%m-%d %H:%M:%S", localtime),
        remediation => $args{remediation} || 'Consult security team'
    };
    
    push @{$self->{results}}, $vuln;
    
    my $severity = lc $vuln->{severity};
    $self->{stats}{vulnerabilities}{$severity}++ if exists $self->{stats}{vulnerabilities}{$severity};
    
    say "[$vuln->{severity}] $vuln->{id}: $vuln->{description}";
}

# Plugin system
package WebPredator::Plugin;

sub new {
    my ($class, %args) = @_;
    
    my $self = {
        scanner => $args{scanner},
        config => $args{config},
        name => $class,
        description => 'Base plugin class',
    };
    
    bless $self, $class;
    return $self;
}

sub execute {
    my $self = shift;
    die "Plugin execute method not implemented";
}

# Example security plugin
package WebPredator::Plugin::CORS;
use base 'WebPredator::Plugin';

sub new {
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    
    $self->{name} = 'CORS Security Checker';
    $self->{description} = 'Checks for misconfigured CORS policies';
    
    return $self;
}

sub execute {
    my $self = shift;
    
    my $url = ($self->{scanner}{ssl} ? 'https://' : 'http://') . 
              $self->{scanner}{host} . ':' . $self->{scanner}{port} . '/';
    
    my $req = HTTP::Request->new(OPTIONS => $url);
    $req->header(
        'Origin' => 'https://attacker.com',
        'Access-Control-Request-Method' => 'GET'
    );
    
    my $res = $self->{scanner}{lwp_ua}->request($req);
    
    if ($res->header('Access-Control-Allow-Origin') && 
        $res->header('Access-Control-Allow-Origin') eq '*') {
        $self->{scanner}->_log_vulnerability(
            id => 'CORS-001',
            description => 'Overly permissive CORS policy detected',
            severity => 'MEDIUM',
            remediation => 'Restrict CORS to specific trusted origins'
        );
    }
}

# Command-line interface
package main;

sub usage {
    print <<"END_USAGE";
WebPredator Web Scanner $VERSION ($RELEASE)

Usage: webpredator.pl [options] -host <host>

Options:
    -host <host>       Target hostname or IP
    -port <port>       Port number (default: 80)
    -ssl               Use SSL/TLS
    -output <file>     Output file (default: report.html)
    -format <format>   Report format (html, json, sarif)
    -threat-intel      Enable threat intelligence
    -api-scan          Enable API security scanning
    -cloud-scan        Enable cloud security checks
    -help              Show this help

Features:
    - Comprehensive web vulnerability scanning
    - Modern protocol support (HTTP/2, WebSockets)
    - API security testing
    - Cloud-native application checks
    - Advanced reporting capabilities
END_USAGE

    exit;
}

# Parse command line
my %opts = ();
GetOptions(
    'host=s'       => \$opts{host},
    'port=i'       => \$opts{port},
    'ssl'          => \$opts{ssl},
    'output=s'     => \$opts{output},
    'format=s'     => \$opts{format},
    'threat-intel' => \$opts{threat_intel},
    'api-scan'     => \$opts{api_scan},
    'cloud-scan'   => \$opts{cloud_scan},
    'help'         => \$opts{help},
) or usage();

usage() if $opts{help} || !$opts{host};

# Initialize and run scanner
my $scanner = WebPredator->new(
    host => $opts{host},
    port => $opts{port},
    ssl  => $opts{ssl},
);

$scanner->scan();
$scanner->generate_report(
    format => $opts{format} || 'html',
    output => $opts{output}
);

exit 0;

__END__

=head1 NAME

webpredator.pl - Advanced web vulnerability scanner

=head1 DESCRIPTION

WebPredator is a next-generation web vulnerability scanner with:

=over 4

=item * Modern web technology support

=item * Comprehensive API security testing

=item * Cloud-native application scanning

=item * Threat intelligence integration

=item * Advanced reporting capabilities

=back

=head1 AUTHOR

WebPredator Security Team

=head1 LICENSE

Proprietary

=head1 WEBSITE

https://webpredator.io