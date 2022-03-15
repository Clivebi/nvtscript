CPE = "cpe:/a:emc:isilon_insightiq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140135" );
	script_version( "2021-10-04T09:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 09:24:26 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2017-01-31 12:44:39 +0100 (Tue, 31 Jan 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2014-4628" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dell EMC Isilon InsightIQ <= 3.1 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_emc_isilon_insightiq_detect.sc" );
	script_mandatory_keys( "emc/isilon_insightiq/detected" );
	script_tag( name: "summary", value: "Dell EMC Isilon InsightIQ is prone to an unspecified cross-site
  scripting (XSS) vulnerability because it fails to sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script
  code  in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Dell EMC Isilon InsightIQ prior to version 3.1." );
	script_tag( name: "solution", value: "Update to version 3.1 or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/71663" );
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
if(version_is_less( version: vers, test_version: "3.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

