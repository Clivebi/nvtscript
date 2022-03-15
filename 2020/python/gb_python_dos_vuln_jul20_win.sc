if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113723" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-07-16 07:51:36 +0000 (Thu, 16 Jul 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-20907" );
	script_name( "Python <= 3.8.3 DoS Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_python_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "python/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Python is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker is able to craft a TAR archive leading to an infinite loop
  when opened by tarfile.open, because _proc_pax lacks header validation." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to deny legitimate users access to the application or exhaust a system's resources." );
	script_tag( name: "affected", value: "Python through version 3.8.3." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_xref( name: "URL", value: "https://bugs.python.org/issue39017" );
	exit( 0 );
}
CPE = "cpe:/a:python:python";
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
if(version_is_less_equal( version: version, test_version: "3.8.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

