if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112633" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-21 11:54:11 +0000 (Wed, 21 Aug 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-15 00:15:00 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-15232" );
	script_name( "Live555 Streaming Media < 2019.08.16 Use-After-Free Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "os_detection.sc", "gb_live555_consolidation.sc" );
	script_mandatory_keys( "Host/runs_windows", "live555/streaming_media/detected" );
	script_tag( name: "summary", value: "Live555 Streaming Media is prone to a Use-After-Free vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists because GenericMediaServer::createNewClientSessionWithId
  can generate the same client session ID in succession, which is mishandled by the MPEG1or2 and Matroska file demultiplexors." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to cause an
  'access after delete' error." );
	script_tag( name: "affected", value: "Live555 Streaming Media before version 2019.08.16." );
	script_tag( name: "solution", value: "Update to version 2019.08.16." );
	script_xref( name: "URL", value: "http://www.live555.com/liveMedia/public/changelog.txt" );
	exit( 0 );
}
CPE = "cpe:/a:live555:streaming_media";
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
if(version_is_less( version: version, test_version: "2019.08.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2019.08.16", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

