if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104078" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Nmap NSE net: lexmark-config" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://www.lexmark.com/vgn/images/portal/Security%20Features%20of%20Lexmark%20MFPs%20v1_1.pdf" );
	script_tag( name: "summary", value: "Retrieves configuration information from a Lexmark S300-S400 printer.

The Lexmark S302 responds to the NTPRequest version probe with its configuration. The response
decodes as mDNS, so the request was modified to resemble an mDNS request as close as possible.
However, the port (9100/udp) is listed as something completely different (HBN3) in documentation
from Lexmark. See the references for more information." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

