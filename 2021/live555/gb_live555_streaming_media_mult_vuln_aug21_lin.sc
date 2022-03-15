CPE = "cpe:/a:live555:streaming_media";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146539" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-20 08:58:12 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-24 14:47:00 +0000 (Tue, 24 Aug 2021)" );
	script_cve_id( "CVE-2021-39282", "CVE-2021-39283" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Live555 Streaming Media < 2021.08.13 Multiple Vulnerabilities - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_live555_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "live555/streaming_media/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Live555 Streaming Media is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-39282: Memory leak in AC3AudioStreamParser for AC3 files

  - CVE-2021-39283: liveMedia/FramedSource.cpp allows an assertion failure and application exit via
  multiple SETUP and PLAY commands" );
	script_tag( name: "affected", value: "Live555 Streaming Media before version 2021.08.13." );
	script_tag( name: "solution", value: "Update to version 2021.08.13 or later." );
	script_xref( name: "URL", value: "http://www.live555.com/liveMedia/public/changelog.txt#[2021.08.13]" );
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
if(version_is_less( version: version, test_version: "2021.08.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2021.08.13", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

