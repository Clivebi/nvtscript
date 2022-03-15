if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100520" );
	script_version( "$Revision: 14233 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-03-09 14:33:24 +0100 (Tue, 09 Mar 2010)" );
	script_bugtraq_id( 38594 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Perforce Socket Hijacking Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38594" );
	script_xref( name: "URL", value: "http://www.perforce.com/perforce/products/p4d.html" );
	script_xref( name: "URL", value: "http://resources.mcafee.com/forms/Aurora_VDTRG_WP" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "perforce_detect.sc" );
	script_require_ports( "Services/perforce", 1666 );
	script_tag( name: "summary", value: "Perforce is prone to a vulnerability that allows attackers to
hijack sockets.

NOTE: For an exploit to succeed, the underlying operating system must
      allow rebinding of a port." );
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
	if( ContainsString( "2008.1", version[2] ) ){
		if(version_is_equal( version: version[3], test_version: "160022" )){
			VULN = TRUE;
		}
	}
	else {
		if(ContainsString( "2009.2", version[2] ) || ContainsString( "2007.3", version[2] )){
			VULN = TRUE;
		}
	}
	if(VULN){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

