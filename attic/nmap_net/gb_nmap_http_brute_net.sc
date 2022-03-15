if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104005" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Nmap NSE net: http-brute" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Performs brute force password auditing against http basic authentication.

SYNTAX:

brute.firstonly:  stop guessing after first password is found
(default: false)

brute.unique:  make sure that each password is only guessed once
(default: true)

http-brute.hostname:  sets the host header in case of virtual hosting

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

brute.mode:  can be user, pass or creds and determines what mode to run
the engine in.

  - user - the unpwdb library is used to guess passwords, every password
password is tried for each user. (The user iterator is in the
outer loop)

  - pass - the unpwdb library is used to guess passwords, each password
is tried for every user. (The password iterator is in the
outer loop)

  - creds- a set of credentials (username and password pairs) are
guessed against the service. This allows for lists of known
or common username and password combinations to be tested.
If no mode is specified and the script has not added any custom
iterator the pass mode will be enabled.

brute.passonly:  iterate over passwords only for services that provide
only a password for authentication. (default: false)

http-brute.path:  points to the path protected by authentication

brute.useraspass:  guess the username as password for each user
(default: true)

http-brute.method:  sets the HTTP method to use (default 'GET')

brute.credfile:  a file containing username and password pairs delimited
by '/'

brute.retries:  the number of times to retry if recoverable failures
occurs. (default: 3)

brute.threads:  the number of initial worker threads, the number of
active threads will be automatically adjusted.

brute.delay:  the number of seconds to wait between guesses (default: 0)

http-max-cache-size:  The maximum memory size (in bytes) of the cache." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

