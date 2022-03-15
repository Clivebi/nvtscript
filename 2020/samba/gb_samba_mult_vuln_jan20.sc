CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143374" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-01-22 08:26:59 +0000 (Wed, 22 Jan 2020)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-29 13:15:00 +0000 (Sat, 29 May 2021)" );
	script_cve_id( "CVE-2019-14902", "CVE-2019-14907" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Samba Multiple Vulnerabilities (CVE-2019-14902, CVE-2019-14907)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "summary", value: "Samba is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Samba is prone to multiple vulnerabilities:

  - Removal of the right to create or modify a subtree would not automatically be taken away on all domain
    controllers (CVE-2019-14902)

  - Crash after failed character conversion at log level 3 or above (CVE-2019-14907)" );
	script_tag( name: "affected", value: "Samba version 4.0 and later." );
	script_tag( name: "solution", value: "Update to version 4.9.18, 4.10.12, 4.11.5 or later." );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2019-14902.html" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2019-14907.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.9.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9.18", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.10.0", test_version2: "4.10.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.10.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.11.0", test_version2: "4.11.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.11.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

