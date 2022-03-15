if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100269" );
	script_version( "$Revision: 14325 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-09-07 09:47:24 +0200 (Mon, 07 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0929" );
	script_bugtraq_id( 36261 );
	script_name( "Perforce Multiple Unspecified Remote Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36261" );
	script_xref( name: "URL", value: "http://www.perforce.com/perforce/products/p4d.html" );
	script_xref( name: "URL", value: "http://intevydis.com/company.shtml" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "perforce_detect.sc" );
	script_require_ports( "Services/perforce", 1666 );
	script_tag( name: "summary", value: "Perforce Server is prone to multiple unspecified remote security
vulnerabilities, including:

  - Multiple unspecified denial-of-service vulnerabilities.

  - An unspecified vulnerability.

An attacker can exploit these issues to crash the affected
application, denying service to legitimate users. Other attacks are
also possible.

Perforce 2008.1/160022 is vulnerable, other versions may also
be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("version_func.inc.sc");
port = get_kb_item( "Services/perforce" );
if(!port){
	exit( 0 );
}
if(!get_tcp_port_state( port )){
	exit( 0 );
}
if(!vers = get_kb_item( NASLString( "perforce/", port, "/version" ) )){
	exit( 0 );
}
if(!isnull( vers )){
	if(!version = split( buffer: vers, sep: "/", keep: 0 )){
		exit( 0 );
	}
	if(!ContainsString( "2008.1", version[2] )){
		exit( 0 );
	}
	if(version_is_equal( version: version[3], test_version: "160022" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

