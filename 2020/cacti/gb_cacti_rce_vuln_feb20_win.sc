CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143548" );
	script_version( "2021-08-16T09:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-02-24 06:36:04 +0000 (Mon, 24 Feb 2020)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-25 18:15:00 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-8813" );
	script_name( "Cacti < 1.2.10 RCE Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Cacti is prone to an authenticated remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "graph_realtime.php in Cacti allows remote attackers to execute arbitrary OS
  commands via shell metacharacters in a cookie, if a guest user has the graph real-time privilege." );
	script_tag( name: "affected", value: "Cacti prior to version 1.2.10." );
	script_tag( name: "solution", value: "Update to version 1.2.10 or later." );
	script_xref( name: "URL", value: "https://shells.systems/cacti-v1-2-8-authenticated-remote-code-execution-cve-2020-8813/" );
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
if(version_is_less( version: version, test_version: "1.2.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.10", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

