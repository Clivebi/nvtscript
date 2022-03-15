if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103322" );
	script_bugtraq_id( 50437 );
	script_cve_id( "CVE-2011-4807", "CVE-2011-4806" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "phpAlbum Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44078" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50437" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18045/" );
	script_xref( name: "URL", value: "http://www.phpalbum.net/dw" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-11-01 08:00:00 +0100 (Tue, 01 Nov 2011)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "phpAlbum is prone to an arbitrary-file-download vulnerability,
multiple cross-site scripting vulnerabilities, and multiple PHP code-
injection vulnerabilities because it fails to sufficiently sanitize
user-supplied data.

An attacker can exploit these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, inject and execute arbitrary malicious PHP code, or download
arbitrary files within the context of the webserver process.

PhpAlbum 0.4.1.16 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/phpalbum", "/phpAlbum", "/phpAlbumnet", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/main.php";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "<title>phpAlbum.net" )){
		url = NASLString( dir, "/main.php?cmd=phpinfo" );
		if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

