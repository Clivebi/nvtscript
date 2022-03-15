CPE = "cpe:/a:clamav:clamav";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811575" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_cve_id( "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420", "CVE-2017-11423" );
	script_bugtraq_id( 100154 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-08-08 14:13:11 +0530 (Tue, 08 Aug 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ClamAV Multiple DoS Vulnerabilities (Aug 2017) - Windows" );
	script_tag( name: "summary", value: "ClamAV is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper calidation for CHM file in 'mspack/lzxd.c' script in
    libmspack 0.5alpha.

  - An improper calidation for CAB file in cabd_read_string function in
    'mspack/cabd.c' script in libmspack 0.5alpha.

  - An improper validation for e-mail message in 'libclamav/message.c'
    script.

  - An improper validation for PE file in wwunpack function in
    'libclamav/wwunpack.c' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause a denial of service or possibly have unspecified other
  impact." );
	script_tag( name: "affected", value: "ClamAV version 0.99.2." );
	script_tag( name: "solution", value: "Update to version 0.99.3-beta1." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://github.com/vrtadmin/clamav-devel/commit/a83773682e856ad6529ba6db8d1792e6d515d7f1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
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
if(vers == "0.99.2"){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.99.3-beta1", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

