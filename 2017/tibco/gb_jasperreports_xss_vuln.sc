CPE = "cpe:/a:tibco:jasperreports_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140529" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-23 12:45:41 +0700 (Thu, 23 Nov 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:28:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2017-5532" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TIBCO JasperReports XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jasperreports_detect.sc" );
	script_mandatory_keys( "jasperreports/installed" );
	script_tag( name: "summary", value: "TIBCO JasperReports contain a vulnerability which may allow a subset of
authorized users to perform persistent cross-site scripting (XSS) attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "The impact of this vulnerability includes the possibility that a malicious
user can gain access to a more privileged account." );
	script_tag( name: "affected", value: "TIBCO JasperReports Server version 6.2.x, 6.3.x and 6.4.0." );
	script_tag( name: "solution", value: "Update to version 6.2.4, 6.3.3, 6.4.2 or later." );
	script_xref( name: "URL", value: "https://www.tibco.com/support/advisories/2017/11/tibco-security-advisory-november-15-2017-tibco-jasperreports-2017-5532" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.2.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.3.0", test_version2: "6.3.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.3.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "6.4.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.4.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

