CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146141" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 06:40:46 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 17:53:00 +0000 (Tue, 29 Jun 2021)" );
	script_cve_id( "CVE-2021-21441" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS XSS Vulnerability (OSA-2021-11)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There is a XSS vulnerability in the ticket overview screens.
  It's possible to collect various information by having an e-mail shown in the overview screen.
  Attack can be performed by sending specially crafted e-mail to the system and it doesn't require
  any user intraction." );
	script_tag( name: "affected", value: "OTRS version 6.0.1 and later and 7.0.x through 7.0.26." );
	script_tag( name: "solution", value: "Update to version 7.0.27 or later." );
	script_xref( name: "URL", value: "https://otrs.com/release-notes/otrs-security-advisory-2021-11/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "6.0.1", test_version2: "7.0.26" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.27", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

