CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811052" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_cve_id( "CVE-2017-8313", "CVE-2017-8312", "CVE-2017-8311", "CVE-2017-8310" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-27 01:29:00 +0000 (Fri, 27 Apr 2018)" );
	script_tag( name: "creation_date", value: "2017-05-24 12:47:56 +0530 (Wed, 24 May 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "VLC Media Player Subtitle Remote Code Execution Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with VLC media player
  and is prone to heap overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the poor state of
  security in the way media player process subtitle files and the large number
  of subtitle formats. There are over 25 subtitle formats in use, each with unique
  features and capabilities. Media player often need to parse together multiple
  subtitle formats to ensure coverage and provide a better user experience. Like
  other, similar situations which involve fragmented software, this results in
  numerous distinct vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to take complete control over any device running them." );
	script_tag( name: "affected", value: "VideoLAN VLC media player before 2.2.5.1 on Windows." );
	script_tag( name: "solution", value: "Upgrade to VideoLAN VLC media player version
  2.2.5.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://blog.checkpoint.com/2017/05/23/hacked-in-translation" );
	script_xref( name: "URL", value: "https://threatpost.com/subtitle-hack-leaves-200-million-vulnerable-to-remote-code-execution" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vlcVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vlcVer, test_version: "2.2.5.1" )){
	report = report_fixed_ver( installed_version: vlcVer, fixed_version: "2.2.5.1" );
	security_message( data: report );
	exit( 0 );
}

