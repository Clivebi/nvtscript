CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142681" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-07-31 05:12:58 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-05 18:00:00 +0000 (Mon, 05 Aug 2019)" );
	script_cve_id( "CVE-2019-11199", "CVE-2019-11200", "CVE-2019-11201" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dolibarr < 9.0.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_tag( name: "summary", value: "Dolibarr is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Dolibarr is prone to multiple vulnerabilities:

  - Stored XSS vulnerability within uploaded files (CVE-2019-11199)

  - Database backup vulnerability (CVE-2019-11200)

  - Authenticated RCE vulnerbability (CVE-2019-11201)" );
	script_tag( name: "affected", value: "Dolibarr prior to version 9.0.3." );
	script_tag( name: "solution", value: "Update to version 9.0.3 or later." );
	script_xref( name: "URL", value: "https://know.bishopfox.com/advisories/dolibarr-version-9-0-1-vulnerabilities" );
	script_xref( name: "URL", value: "https://github.com/Dolibarr/dolibarr/blob/develop/ChangeLog" );
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
if(version_is_less( version: version, test_version: "9.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

