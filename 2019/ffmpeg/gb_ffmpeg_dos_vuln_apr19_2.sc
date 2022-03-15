if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113375" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-24 13:59:25 +0000 (Wed, 24 Apr 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-06 21:29:00 +0000 (Mon, 06 May 2019)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-11339" );
	script_bugtraq_id( 108037 );
	script_name( "FFmpeg 4.x < 4.0.4, 4.1.x < 4.1.2 Denial of Service (DoS) Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ffmpeg_detect_lin.sc" );
	script_mandatory_keys( "FFmpeg/Linux/Ver" );
	script_tag( name: "summary", value: "FFmpeg is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The studio profile decoder in libavcodec/mpeg4videodec.c allows remote attackers
  to cause an out-of-array access via crafted MPEG-4 video data." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to cause a denial of service
  or possibly have other unspecified impact." );
	script_tag( name: "affected", value: "FFmpeg versions 4.0.0 through 4.0.3 and 4.1.0 through 4.1.1." );
	script_tag( name: "solution", value: "Update to version 4.0.4 or 4.1.2 respectively." );
	script_xref( name: "URL", value: "https://github.com/FFmpeg/FFmpeg/commit/1f686d023b95219db933394a7704ad9aa5f01cbb" );
	script_xref( name: "URL", value: "https://github.com/FFmpeg/FFmpeg/commit/d227ed5d598340e719eff7156b1aa0a4469e9a6a" );
	exit( 0 );
}
CPE = "cpe:/a:ffmpeg:ffmpeg";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.3" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.1.0", test_version2: "4.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.2" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

