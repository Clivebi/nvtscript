if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803532" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:21 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: dns-random-srcport" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "https://www.dns-oarc.net/oarc/services/porttest" );
	script_tag( name: "summary", value: "Checks a DNS server for the predictable-port recursion vulnerability. Predictable source ports can
make a DNS server vulnerable to cache poisoning attacks (see CVE-2008-1447).

The script works by querying porttest.dns-oarc.net (see references).  Be aware that any targets against which this script is run will
be sent to and potentially recorded by one or more DNS servers and the porttest server. In addition
your IP address will be sent along with the porttest query to the DNS server running on the target." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

