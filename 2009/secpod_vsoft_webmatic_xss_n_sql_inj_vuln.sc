if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901088" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-4379", "CVE-2009-4380" );
	script_bugtraq_id( 37335 );
	script_name( "Valarsoft Webmatic Multiple XSS and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37735" );
	script_xref( name: "URL", value: "http://www.valarsoft.com/index.php?stage=0&section=5&newsID=165&action=6" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_valarsoft_webmatic_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "valarsoft/webmatic/detected" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause Cross-Site Scripting or
  SQL Injection attacks by executing arbitrary codes within the context of the affected application." );
	script_tag( name: "affected", value: "Valarsoft Webmatic prior to 3.0.3" );
	script_tag( name: "insight", value: "- Certain unspecified input is not properly sanitised before being returned to
  the user. This can be exploited to execute arbitrary HTML and script code in
  a user's browser session in the context of an affected site.

  - Certain unspecified input is not properly sanitised before being used in SQL
  queries. This can be exploited to manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Valarsoft Webmatic version 3.0.3." );
	script_tag( name: "summary", value: "This host is running Valarsoft Webmatic and is prone to multiple
  Cross-Site Scripting and SQL Injection vulnerabilities." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
webmaticPort = http_get_port( default: 80 );
webmaticVer = get_kb_item( "www/" + webmaticPort + "/Valarsoft/Webmatic" );
if(!webmaticVer){
	exit( 0 );
}
webmaticVer = eregmatch( pattern: "^(.+) under (/.*)$", string: webmaticVer );
if(webmaticVer[1]){
	if(version_is_less( version: webmaticVer[1], test_version: "3.0.3" )){
		report = report_fixed_ver( installed_version: webmaticVer[1], fixed_version: "3.0.3" );
		security_message( port: webmaticPort, data: report );
	}
}

