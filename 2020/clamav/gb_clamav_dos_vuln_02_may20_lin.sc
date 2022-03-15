if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112750" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-18 11:44:00 +0000 (Mon, 18 May 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-29 01:15:00 +0000 (Fri, 29 May 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-3341" );
	script_name( "ClamAV 0.101 - 0.102.2 DoS Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_remote_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "ClamAV/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "ClamAV is prone to a denial-of-service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Improper size checking of a buffer used to initialize AES decryption routines results in an out-of-bounds read, which may cause a crash." );
	script_tag( name: "impact", value: "Successful exploitation would cause a denial-of-service condition." );
	script_tag( name: "affected", value: "ClamAV versions 0.101 through 0.102.2." );
	script_tag( name: "solution", value: "Update to version 0.102.3 or later." );
	script_xref( name: "URL", value: "https://blog.clamav.net/2020/05/clamav-01023-security-patch-released.html" );
	exit( 0 );
}
CPE = "cpe:/a:clamav:clamav";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "0.101", test_version2: "0.102.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.102.3", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

