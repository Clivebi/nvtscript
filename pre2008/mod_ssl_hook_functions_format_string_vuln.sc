CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13651" );
	script_version( "2021-02-25T13:36:35+0000" );
	script_tag( name: "last_modification", value: "2021-02-25 13:36:35 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 10736 );
	script_cve_id( "CVE-2004-0700" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Apache HTTP Server 'mod_ssl' Hook Functions Format String Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/http_server/http/detected" );
	script_tag( name: "solution", value: "Update to version 2.8.19 or later." );
	script_tag( name: "summary", value: "The remote host is using a version vulnerable of mod_ssl
  which is older than 2.8.19. There is a format string condition in the log functions of the
  remote module which may allow an attacker to execute arbitrary code on the remote host." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "Darwin" )){
	exit( 0 );
}
serv = strstr( banner, "Server" );
if(!ContainsString( serv, "Apache/" )){
	exit( 0 );
}
if(ContainsString( serv, "Apache/2" )){
	exit( 0 );
}
if(ContainsString( serv, "Apache-AdvancedExtranetServer/2" )){
	exit( 0 );
}
if(ereg( pattern: ".*mod_ssl/(1.*|2\\.([0-7]\\..*|8\\.([0-9]|1[0-8])[^0-9])).*", string: serv )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

