CPE = "cpe:/a:msf_emby_project:msf_emby";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146696" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-10 08:47:56 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-16 14:22:00 +0000 (Thu, 16 Sep 2021)" );
	script_cve_id( "CVE-2021-32833" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "Emby Server <= 4.6.4.0 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_emby_server_http_detect.sc" );
	script_mandatory_keys( "emby/media_server/detected" );
	script_tag( name: "summary", value: "Emby Server is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Emby Server has an arbitrary file read in
  /Videos/Id/hls/PlaylistId/SegmentId.SegmentContainer and an unauthenticated arbitrary image file
  read in /Images/Ratings/theme/name and /Images/MediaInfo/theme/name." );
	script_tag( name: "affected", value: "Emby Server version 4.6.4.0 and prior." );
	script_tag( name: "solution", value: "No known solution is available as of 10th September, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://securitylab.github.com/advisories/GHSL-2021-051-emby/" );
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
if(version_is_less_equal( version: version, test_version: "4.6.4.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

