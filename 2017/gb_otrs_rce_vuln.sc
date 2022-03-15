CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112139" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-24 08:52:38 +0100 (Fri, 24 Nov 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 18:57:00 +0000 (Wed, 08 May 2019)" );
	script_cve_id( "CVE-2017-16664" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker who is logged into OTRS as an agent can request special URLs
from OTRS which can lead to the execution of shell commands with the permissions of the web server user." );
	script_tag( name: "affected", value: "OTRS 5.0.x up to and including 5.0.23, OTRS 4.0.x up to and including 4.0.25 and OTRS 3.3.x up to and including 3.3.19" );
	script_tag( name: "solution", value: "Upgrade to OTRS 3.3.20, 4.0.26, 5.0.24 or later." );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2017-07-security-update-otrs-framework/" );
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
if(version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.19" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.20" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.25" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.26" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.23" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.24" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

