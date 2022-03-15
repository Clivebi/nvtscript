if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103268" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-22 13:43:24 +0200 (Thu, 22 Sep 2011)" );
	script_bugtraq_id( 49587 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Papoo CMS Light Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49587" );
	script_xref( name: "URL", value: "http://www.papoo.de/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519612" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Papoo CMS Light is prone to multiple cross-site scripting
vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary HTML and
script code in the browser of an unsuspecting user in the context of
the affected site. This may let the attacker steal cookie-based
authentication credentials and launch other attacks.

Papoo CMS Light 4.0 is vulnerable. Other versions may also be
affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/cms", "/papoo", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php/\"></a><script>alert(/", vt_strings["lowercase"], "/);</script>" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/" + vt_strings["lowercase"] + "/\\);</script>", check_header: TRUE, extra_check: "Papoo" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

