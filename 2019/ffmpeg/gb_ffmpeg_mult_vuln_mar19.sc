if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113356" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-14 12:23:14 +0200 (Thu, 14 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 19:15:00 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-9718", "CVE-2019-9721" );
	script_bugtraq_id( 107384 );
	script_name( "FFmpeg <= 4.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ffmpeg_detect_lin.sc" );
	script_mandatory_keys( "FFmpeg/Linux/Ver" );
	script_tag( name: "summary", value: "FFmpeg is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in the subtitle decoder allows attackers
  to hog the CPU via a crafted video file in Matroska format:

  - because ff_htmlmarkup_to_ass in libavcodec/htmlsubtitles.c has a complex
    format argument to sscanf

  - because handle_open_brace in libavcodec/htmlsubtitles.c has a complex
    format argument to sscanf" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to exhaust the target
  system's CPU resources." );
	script_tag( name: "affected", value: "FFmpeg through version 4.1.0." );
	script_tag( name: "solution", value: "Update to version 4.1.1." );
	script_xref( name: "URL", value: "https://git.ffmpeg.org/gitweb/ffmpeg.git/commit/894995c41e0795c7a44f81adc4838dedc3932e65" );
	script_xref( name: "URL", value: "https://git.ffmpeg.org/gitweb/ffmpeg.git/commit/1f00c97bc3475c477f3c468cf2d924d5761d0982" );
	exit( 0 );
}
CPE = "cpe:/a:ffmpeg:ffmpeg";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.1" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

