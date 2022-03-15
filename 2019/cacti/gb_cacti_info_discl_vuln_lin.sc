CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143251" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-12-16 06:48:28 +0000 (Mon, 16 Dec 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-20 03:15:00 +0000 (Fri, 20 Dec 2019)" );
	script_cve_id( "CVE-2019-16723" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti < 1.2.7 Information Disclosure Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "In Cacti, authenticated users may bypass authorization checks (for viewing a
  graph) via a direct graph_json.php request with a modified local_graph_id parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Cacti version 1.2.6 and prior." );
	script_tag( name: "solution", value: "Update to version 1.2.7 or later." );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/2964" );
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
if(version_is_less( version: version, test_version: "1.2.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

