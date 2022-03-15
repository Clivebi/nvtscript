CPE = "cpe:/a:clamav:clamav";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806016" );
	script_version( "2021-04-15T09:30:02+0000" );
	script_cve_id( "CVE-2015-2668", "CVE-2015-2222", "CVE-2015-2221", "CVE-2015-2170" );
	script_bugtraq_id( 74472, 74443 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-15 09:30:02 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-08-17 12:16:12 +0530 (Mon, 17 Aug 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ClamAV Multiple DoS Vulnerabilities (Aug 2015) - Windows" );
	script_tag( name: "summary", value: "ClamAV is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - an error that is triggered when handling a specially crafted xz archive file,
  which can cause an infinite loops.

  - an error in the 'cli_scanpe' function in pe.c script that is triggered when
  handling petite packed files.

  - an error in the 'yc_poly_emulator' function in yc.c script that is
  triggered when handling a specially crafted y0da cryptor file.

  - an error in the 'pefromupx' function of the UPX decoder that is
  triggered when handling specially crafted files." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to crash the application." );
	script_tag( name: "affected", value: "ClamAV versions before 0.98.7." );
	script_tag( name: "solution", value: "Upgrade to ClamAV version 0.98.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://blog.clamav.net/2015/04/clamav-0987-has-been-released.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "0.98.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.98.7", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

