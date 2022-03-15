if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103197" );
	script_version( "2021-05-17T11:26:07+0000" );
	script_tag( name: "last_modification", value: "2021-05-17 11:26:07 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2011-08-11 14:25:35 +0200 (Thu, 11 Aug 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 49022 );
	script_name( "Community Server 'TagSelector.aspx' XSS Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49022" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519156" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Community Server is prone to a cross-site scripting XSS
  vulnerability because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Community Server 2007 and 2008 are vulnerable. Other versions
  may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/utility/TagSelector.aspx?TagEditor=%27)%3C/script%3E%3Cscript%3Ealert(%27", vt_strings["lowercase"], "%27)%3C/script%3E" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('" + vt_strings["lowercase"] + "'\\)</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

