CPE = "cpe:/a:ibm:bigfix_webreports";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140070" );
	script_bugtraq_id( 94155 );
	script_cve_id( "CVE-2016-0396" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2020-12-07T13:33:44+0000" );
	script_name( "IBM BigFix Platform Remote Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/94155" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21993206" );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to execute arbitrary
  commands within the context of the application." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory for more information." );
	script_tag( name: "summary", value: "IBM BigFix Platform is prone to a remote command-injection vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "50" );
	script_tag( name: "last_modification", value: "2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2016-11-21 10:40:03 +0100 (Mon, 21 Nov 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ibm_bigfix_web_reports_detect.sc" );
	script_mandatory_keys( "ibm/bigfix_web_reports/version" );
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
if(IsMatchRegexp( vers, "^9\\." )){
	if(version_is_less( version: vers, test_version: "9.5.3" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the upgrade-patch 9.5.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

