if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801454" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-3418" );
	script_bugtraq_id( 43145 );
	script_name( "NetArt Media Car Portal Multiple Cross-site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41366" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61728" );
	script_xref( name: "URL", value: "http://pridels-team.blogspot.com/2010/09/netartmedia-car-portal-v20-xss-vuln.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "Input passed via the 'y' parameter to 'include/images.php' and
  'car_id' parameter to 'index.php' are not properly sanitised." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running NetArt Media Car Portal and is prone to
  multiple cross-site scripting vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "NetArt Media Car Portal version 2.0" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/car_portal", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">Car Portal<" )){
		req = http_get( item: NASLString( dir, "/include/images.php?y=<script>" + "alert(\"", vt_strings["lowercase"], "\")</script>" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ereg( pattern: "^HTTP/1\\.[01] 200", string: res ) && ContainsString( res, "<script>alert(\"" + vt_strings["lowercase"] + "\")</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

