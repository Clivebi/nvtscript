if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104095" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_cve_id( "CVE-2008-1447" );
	script_bugtraq_id( 30131 );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-24 18:19:00 +0000 (Tue, 24 Mar 2020)" );
	script_name( "Nmap NSE net: dns-random-txid" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "https://www.dns-oarc.net/oarc/services/txidtest" );
	script_tag( name: "summary", value: "Checks a DNS server for the predictable-TXID DNS recursion vulnerability.  Predictable TXID values
can make a DNS server vulnerable to cache poisoning attacks (see CVE-2008-1447).

The script works by querying txidtest.dns-oarc.net (see the referenced link).  Be aware that any targets against which this script is run will
be sent to and potentially recorded by one or more DNS servers and the txidtest server. In addition
your IP address will be sent along with the txidtest query to the DNS server running on the target." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

