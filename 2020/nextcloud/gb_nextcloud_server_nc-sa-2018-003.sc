CPE = "cpe:/a:nextcloud:nextcloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108711" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-02-07 08:23:29 +0000 (Fri, 07 Feb 2020)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:40:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2018-3761" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Nextcloud Server < 12.0.8, < 13.0.3 Improper Input Vulnerability (NC-SA-2018-003)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nextcloud_detect.sc" );
	script_mandatory_keys( "nextcloud/installed" );
	script_tag( name: "summary", value: "Nextcloud Server is prone to an improper input vulnerability." );
	script_tag( name: "insight", value: "Improper validation of input allowed an attacker with access
  to the OAuth2 refresh token to obtain new tokens." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Nextcloud server versions prior 12.0.8 and prior 13.0.3." );
	script_tag( name: "solution", value: "Update to version 12.0.8, 13.0.3 or later." );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=NC-SA-2018-003" );
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
if(version_is_less( version: version, test_version: "12.0.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.0.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "13.0.0", test_version2: "13.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "13.0.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

