if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803521" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:10 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: whois" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Queries the WHOIS services of Regional Internet Registries (RIR)and attempts to retrieve
information about the IP Address Assignment which contains the Target IP Address.

The fields displayed contain information about the assignment and the organisation responsible for
managing the address space. When output verbosity is requested on the Nmap command line
('-v') extra information about the assignment will be displayed.

To determine which of the RIRs to query for a given Target IP Address this script utilises
Assignments Data hosted by IANA. The data is cached locally and then parsed for use as a lookup
table.  The locally cached files are refreshed periodically to help ensure the data is current.  If,
for any reason, these files are not available to the script then a default sequence of Whois
services are queried in turn until: the desired record is found or a referral to another (defined)
Whois service is found or until the sequence is exhausted without finding either a referral or the
desired record.

The script will recognize a referral to another Whois service if that service is defined in the
script and will continue by sending a query to the referred service.  A record is assumed to be the
desired one if it does not contain a referral.

To reduce the number unnecessary queries sent to Whois services a record cache is employed and the
entries in the cache can be applied to any targets within the range of addresses represented in the
record.

In certain circumstances, the ability to cache responses prevents the discovery of other, smaller IP
address assignments applicable to the target because a cached response is accepted in preference to
sending a Whois query.  When it is important to ensure that the most accurate information about the
may use a cached record to a size that helps ensure that smaller assignments will be discovered.

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

whodb:  Takes any of the following values, which may be combined:

  - 'whodb=nofile' Prevent the use of IANA assignments data and instead query the default services.

  - 'whodb=nofollow' Ignore referrals and instead display the first record obtained.

  - 'whodb=nocache' Prevent the acceptance of records in the cache when they apply to large ranges of addresses.

  - 'whodb=[service-ids]' Redefine the default services to query.  Implies 'nofile'.

http-max-cache-size:  The maximum memory size (in bytes) of the cache." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

