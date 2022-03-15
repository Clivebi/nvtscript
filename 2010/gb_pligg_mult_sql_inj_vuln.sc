if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801258" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2010-2577", "CVE-2010-3013" );
	script_bugtraq_id( 42408 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)" );
	script_name( "Pligg Multiple SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40931" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2010-111/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "pligg_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "pligg/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information." );
	script_tag( name: "affected", value: "Pligg CMS Version 1.1.0 and prior." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied inputs via the
  'title' parameter in storyrss.php and story.php and 'role' parameter in
  groupadmin.php that allows attacker to manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Pligg CMS Version 1.1.1 or later." );
	script_tag( name: "summary", value: "The host is running Pligg CMS and is prone to multiple SQL injection
  vulnerabilities." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(ver = get_version_from_kb( port: port, app: "pligg" )){
	if(version_is_less( version: ver, test_version: "1.1.1" )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "1.1.1" );
		security_message( port: port, data: report );
	}
}

