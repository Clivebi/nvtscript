CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808221" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2016-5108" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "creation_date", value: "2016-06-13 13:25:43 +0530 (Mon, 13 Jun 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "VLC Media Player QuickTime IMA File Denial of Service Vulnerability June16 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with VLC media player
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a buffer overflow
  vulnerability in the 'DecodeAdpcmImaQT' function in 'modules/codec/adpcm.c'
  script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service (crash) and possibly execute arbitrary
  code via crafted QuickTime IMA file." );
	script_tag( name: "affected", value: "VideoLAN VLC media player before 2.2.4
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to VideoLAN VLC media player version
  2.2.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1036009" );
	script_xref( name: "URL", value: "http://www.videolan.org/security/sa1601.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vlcVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vlcVer, test_version: "2.2.4" )){
	report = report_fixed_ver( installed_version: vlcVer, fixed_version: "2.2.4" );
	security_message( data: report );
	exit( 0 );
}

