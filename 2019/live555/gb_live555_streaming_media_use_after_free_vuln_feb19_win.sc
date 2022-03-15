if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113355" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-13 11:45:16 +0200 (Wed, 13 Mar 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-07 06:15:00 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-7314" );
	script_name( "Live555 Streaming Media < 2019.02.03 Use-After-Free Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "os_detection.sc", "gb_live555_consolidation.sc" );
	script_mandatory_keys( "Host/runs_windows", "live555/streaming_media/detected" );
	script_tag( name: "summary", value: "Live555 Streaming Media is prone to a Use-After-Free vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists because Live555 Streaming Media mishandles the
  termination of an RTSP stream after RTP/RTCP-over-RTSP has been set up,
  which could lead to a Use-After-Free error." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to crash the RTSP server.
  Other impact, such as code execution, may also be possible." );
	script_tag( name: "affected", value: "Live555 Streaming Media before version 2019.02.03." );
	script_tag( name: "solution", value: "Update to version 2019.02.03." );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00037.html" );
	exit( 0 );
}
CPE = "cpe:/a:live555:streaming_media";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2019.02.03" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2019.02.03" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

