CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100213" );
	script_version( "2021-04-19T14:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-04-19 14:01:20 +0000 (Mon, 19 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-05-28 16:49:18 +0200 (Thu, 28 May 2009)" );
	script_cve_id( "CVE-2008-0786", "CVE-2008-0785", "CVE-2008-0784", "CVE-2008-0783" );
	script_bugtraq_id( 27749 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Cacti < 0.8.7b Multiple Input Validation Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "cacti_detect.sc" );
	script_mandatory_keys( "cacti/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/27749" );
	script_tag( name: "solution", value: "Update to version 0.8.7b or later." );
	script_tag( name: "summary", value: "Cacti is prone to multiple unspecified input-validation
  vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  - Multiple cross-site scripting vulnerabilities

  - Multiple SQL-injection vulnerabilities

  - An HTTP response-splitting vulnerability" );
	script_tag( name: "impact", value: "Attackers may exploit these vulnerabilities to influence or
  misrepresent how web content is served, cached, or interpreted, to compromise the application, to
  access or modify data, to exploit vulnerabilities in the underlying database, or to execute
  arbitrary script code in the browser of an unsuspecting user." );
	script_tag( name: "affected", value: "Cacti version 0.8.7a and prior." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "0.8.7b" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.8.7b" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

