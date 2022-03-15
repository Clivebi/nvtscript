CPE = "cpe:/a:concrete5:concrete5";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144166" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-25 05:28:32 +0000 (Thu, 25 Jun 2020)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 15:54:00 +0000 (Fri, 31 Jul 2020)" );
	script_cve_id( "CVE-2020-14961", "CVE-2020-11476", "CVE-2020-24986" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Concrete5 < 8.5.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_concrete5_detect.sc" );
	script_mandatory_keys( "concrete5/installed" );
	script_tag( name: "summary", value: "Concrete5 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - The sort direction is not constrained to a valid asc or desc value (CVE-2020-14961)

  - Unrestricted upload of files with dangerous types such as a .phar files (CVE-2020-11476)

  - Unrestricted Upload of files with dangerous types such as a .php files via File Manager (CVE-2020-24986)" );
	script_tag( name: "affected", value: "Concrete5 versions prior to 8.5.3." );
	script_tag( name: "solution", value: "Update to version 8.5.3 or later." );
	script_xref( name: "URL", value: "https://github.com/concrete5/concrete5/pull/8651" );
	script_xref( name: "URL", value: "https://github.com/concrete5/concrete5/pull/8713" );
	script_xref( name: "URL", value: "https://github.com/concrete5/concrete5/pull/8335" );
	script_xref( name: "URL", value: "https://github.com/concrete5/concrete5/releases/tag/8.5.3" );
	script_xref( name: "URL", value: "https://herolab.usd.de/security-advisories/usd-2020-0041/" );
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
if(version_is_less( version: version, test_version: "8.5.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

