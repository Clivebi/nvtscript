CPE = "cpe:/a:clamav:clamav";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814147" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-15378" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-17 15:04:36 +0530 (Wed, 17 Oct 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Clam AntiVirus 'unmew11()' DoS Vulnerability - Linux" );
	script_tag( name: "summary", value: "ClamAV is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw related to the MEW unpacker within
  the 'unmew11()' function (libclamav/mew.c) can be exploited to trigger an
  invalid read memory access via a specially crafted EXE file." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause denial of service and." );
	script_tag( name: "affected", value: "ClamAV AntiVirus versions before 0.100.2." );
	script_tag( name: "solution", value: "Update to version 0.100.2 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bugzilla.clamav.net/show_bug.cgi?id=12170" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_remote_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "ClamAV/remote/Ver", "Host/runs_unixoide" );
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
if(version_is_less( version: vers, test_version: "0.100.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.100.2", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

