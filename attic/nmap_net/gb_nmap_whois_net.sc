if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104062" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: whois" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Queries the WHOIS services of Regional Internet Registries (RIR) and attempts to retrieve
information about the IP Address Assignment which contains the Target IP Address.

In using this script your IP address will be sent to iana.org. Additionally your address and the
address of the target of the scan will be sent to one of the RIRs.

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
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

