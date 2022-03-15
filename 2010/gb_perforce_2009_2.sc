if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100519" );
	script_version( "$Revision: 14323 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-03-09 14:33:24 +0100 (Tue, 09 Mar 2010)" );
	script_bugtraq_id( 38590, 38591, 38586 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Perforce 2009.2 Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38590" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38591" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38586" );
	script_xref( name: "URL", value: "http://www.perforce.com/perforce/products/p4d.html" );
	script_xref( name: "URL", value: "http://resources.mcafee.com/forms/Aurora_VDTRG_WP" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "perforce_detect.sc" );
	script_require_ports( "Services/perforce", 1666 );
	script_tag( name: "summary", value: "Perforce Server is prone to Multiple Vulnerabilities.

1. An information-disclosure vulnerability.
An attacker can exploit this issue gain access to sensitive
information that may lead to further attacks.

2. A directory-traversal vulnerability.
An attacker can exploit this issue to overwrite arbitrary files within
the context of the application. Successful exploits may compromise the
affected application and possibly the underlying computer.

3. A security-bypass vulnerability.
An attacker can exploit this issue to change a user's password,
thereby aiding in further attacks.

Perforce Server 2009.2 is vulnerable, other versions may also
be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
	if(version_is_equal( version: version[2], test_version: "2009.2" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

