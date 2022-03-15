CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106367" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-02 09:37:45 +0700 (Wed, 02 Nov 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2016-9139" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker could trick an authenticated agent or customer into opening a
malicious attachment which could lead to the execution of JavaScript in OTRS context." );
	script_tag( name: "affected", value: "OTRS 3.3.x, 4.0.x and 5.0.x" );
	script_tag( name: "solution", value: "Upgrade to OTRS 3.3.16 4.0.19 and 5.0.14 or later." );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2016-02-security-update-otrs/" );
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
if(version_is_less( version: version, test_version: "3.3.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.16" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.19" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.14" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

