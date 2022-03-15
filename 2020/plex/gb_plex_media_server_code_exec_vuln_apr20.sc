CPE = "cpe:/a:plex:plex_media_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143755" );
	script_version( "2021-08-16T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-04-23 06:59:10 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-28 19:05:00 +0000 (Tue, 28 Apr 2020)" );
	script_cve_id( "CVE-2020-5740" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Plex Media Server < 1.19.2.2673 Local Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_plex_media_server_remote_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "plex_media_server/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Plex Media Server is prone to a local unauthenticated code execution vulnerability." );
	script_tag( name: "insight", value: "Improper Input Validation in Plex Media Server on Windows allows a local,
  unauthenticated attacker to execute arbitrary Python code with SYSTEM privileges." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Plex Media Server prior to version 1.19.2.2673 on Windows." );
	script_tag( name: "solution", value: "Update to version 1.19.2.2673 or later." );
	script_xref( name: "URL", value: "https://www.tenable.com/security/research/tra-2020-25" );
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
if(version_is_less( version: version, test_version: "1.19.2.2673" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.19.2.2673", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

