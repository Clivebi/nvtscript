if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18628" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 14099 );
	script_xref( name: "OSVDB", value: "11025" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "YaPiG Password Protected Directory Access Flaw" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote version of YaPiG a flaw that can let a malicious user view images in
  password protected directories." );
	script_tag( name: "impact", value: "Successful exploitation of this issue may allow an attacker to access
  unauthorized images on a vulnerable server." );
	script_xref( name: "URL", value: "http://sourceforge.net/tracker/index.php?func=detail&aid=842990&group_id=93674&atid=605076" );
	script_xref( name: "URL", value: "http://sourceforge.net/tracker/index.php?func=detail&aid=843736&group_id=93674&atid=605076" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/yapig", "/gallery", "/photos", "/photo", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	res = http_get_cache( item: url, port: port );
	if(!res){
		continue;
	}
	if(egrep( pattern: "Powered by .*YaPig.* V0\\.([0-8][0-9]($|[^0-9])|9([0-3]|4[a-u]))", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

