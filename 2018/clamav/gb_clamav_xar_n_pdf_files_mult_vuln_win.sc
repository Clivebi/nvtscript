CPE = "cpe:/a:clamav:clamav";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812577" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-0202", "CVE-2018-1000085" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-26 16:02:00 +0000 (Tue, 26 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-03-21 11:04:51 +0530 (Wed, 21 Mar 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ClamAV 'PDF' and 'XAR Files Parsing Multiple Vulnerabilities - Windows" );
	script_tag( name: "summary", value: "ClamAV is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - An incorrectly handled parsing certain PDF files and

  - An incorrectly handled parsing certain XAR files." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause a denial of service and potentially execute arbitrary code
  on the affected device." );
	script_tag( name: "affected", value: "ClamAV version 0.99.3 and prior." );
	script_tag( name: "solution", value: "Update to version 0.99.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://github.com/Cisco-Talos/clamav-devel/commit/d96a6b8bcc7439fa7e3876207aa0a8e79c8451b6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_clamav_remote_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "ClamAV/remote/Ver", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "0.99.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.99.4", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

