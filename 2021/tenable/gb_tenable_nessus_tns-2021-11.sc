CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118115" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-16 16:11:43 +0200 (Wed, 16 Jun 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 23:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_cve_id( "CVE-2018-20843", "CVE-2019-15903", "CVE-2019-16168", "CVE-2021-20099", "CVE-2021-20100" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Tenable Nessus < 8.15.0 Multiple Vulnerabilities (TNS-2021-11) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nessus_web_server_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "nessus/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Tenable Nessus is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple local privilege escalation vulnerabilities exist, which
  could allow an authenticated, local administrator to run specific Windows executables as the
  Nessus host.

  Additionally, two third-party components (expat, sqlite) were found to contain vulnerabilities." );
	script_tag( name: "affected", value: "Tenable Nessus prior to version 8.15.0 on Windows." );
	script_tag( name: "solution", value: "Update to version 8.15.0 or later.

  Note: Version 8.15.0 includes fixed versions of expat (2.2.10) and sqlite (3.34.1)." );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2021-11" );
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
if(version_is_less( version: version, test_version: "8.15.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.15.0", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

