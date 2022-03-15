CPE = "cpe:/a:novo-ws:orbis_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801404" );
	script_version( "2021-08-02T13:28:43+0000" );
	script_tag( name: "last_modification", value: "2021-08-02 13:28:43 +0000 (Mon, 02 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-2669" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Orbis CMS 'editor-body.php' XSS Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_orbis_cms_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "orbis/cms/http/detected" );
	script_tag( name: "summary", value: "Orbis CMS is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to an input passed via the 's' parameter to
  'admin/editors/text/editor-body.php', which is not properly sanitised before being returned to
  the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Orbis CMS version 1.0.2 and prior." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40474" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/60087" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/admin/editors/text/editor-body.php?s=\"><script>alert(123456789)</script>\"";
if(http_vuln_check( port: port, url: url, pattern: "script>alert(123456789)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

