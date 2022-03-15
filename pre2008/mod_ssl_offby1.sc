CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11039" );
	script_version( "2021-02-25T13:36:35+0000" );
	script_tag( name: "last_modification", value: "2021-02-25 13:36:35 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5084 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_cve_id( "CVE-2002-0653" );
	script_xref( name: "SuSE", value: "SUSE-SA:2002:028" );
	script_name( "Apache HTTP Server 'mod_ssl' Off By One Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Thomas Reinke" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/http_server/http/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to version 2.8.10 or later." );
	script_tag( name: "summary", value: "The remote host is using a version of mod_ssl which is
  older than 2.8.10.

  This version is vulnerable to an off by one buffer overflow which may allow a user with
  write access to .htaccess files to execute arbitrary code on the system with permissions
  of the web server." );
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
if(ereg( pattern: ".*mod_ssl/(1.*|2\\.([0-7]\\..*|8\\.[0-9][^0-9])).*", string: serv )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

