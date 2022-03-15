if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96034" );
	script_version( "$Revision: 10612 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Check SSL on Apache" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_tag( name: "summary", value: "This script checks if SSL on Port 443 on an Apache Server enabled." );
	exit( 0 );
}
require("misc_func.inc.sc");
soc = http_open_socket( 443 );
if(!soc){
	log_message( port: 0, proto: "IT-Grundschutz", data: NASLString( "No access to Port 443." ) );
	set_kb_item( name: "GSHB/APACHE/SSL", value: "inapplicable" );
	exit( 0 );
}
send( socket: soc, data: "GET / HTTP/1.0\r\n\r\n" );
banner = recv( socket: soc, length: 65535 );
http_close_socket( soc );
if(!banner){
	log_message( port: 0, proto: "IT-Grundschutz", data: NASLString( "No Banner received through Port 443" ) );
	set_kb_item( name: "GSHB/APACHE/SSL", value: "error" );
	set_kb_item( name: "GSHB/APACHE/SSL/log", value: "IT-Grundschutz: No Banner received through Port 443" );
	exit( 0 );
}
if( egrep( pattern: "Server: Apache", string: banner ) ){
	set_kb_item( name: "GSHB/APACHE/SSL", value: "false" );
	exit( 0 );
}
else {
	if( egrep( pattern: "Reason: You're speaking plain HTTP to an SSL-enabled server port.", string: banner ) ){
		set_kb_item( name: "GSHB/APACHE/SSL", value: "true" );
		exit( 0 );
	}
	else {
		set_kb_item( name: "GSHB/APACHE/SSL", value: "inapplicable" );
	}
}
exit( 0 );

