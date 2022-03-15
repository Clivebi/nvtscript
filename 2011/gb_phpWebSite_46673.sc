if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103107" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-03-04 13:25:07 +0100 (Fri, 04 Mar 2011)" );
	script_bugtraq_id( 46673 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "phpWebSite 'local' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46673" );
	script_xref( name: "URL", value: "http://phpwebsite.appstate.edu/" );
	script_xref( name: "URL", value: "http://www.autosectools.com/Advisories/phpWebSite.1.7.1_Reflected.Cross-site.Scripting_131.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_phpWebSite_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpwebsite/detected" );
	script_tag( name: "summary", value: "phpWebSite is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This can allow the attacker to steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "affected", value: "phpWebSite 1.7.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "phpWebSite" )){
	exit( 0 );
}
url = NASLString( dir, "/javascript/editors/fckeditor/editor/custom.php?local=<script>alert(/vt-xss-test/)</script>" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/vt-xss-test/\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

