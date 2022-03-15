CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805312" );
	script_version( "2020-04-20T09:38:23+0000" );
	script_cve_id( "CVE-2010-2062" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 09:38:23 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2015-01-05 11:42:27 +0530 (Mon, 05 Jan 2015)" );
	script_name( "VLC Media Player 'real_get_rdt_chunk' BOF Vulnerability-02 Jan15 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with VLC media player
  and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The error exists due to an integer
  underflow in the 'real_get_rdt_chunk' function within
  modules/access/rtsp/real.c script." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attacker to execute an arbitrary code within the context of the VLC
  media player and potentially compromise a user's system." );
	script_tag( name: "affected", value: "VideoLAN VLC media player before 1.0.1
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to VideoLAN VLC media player
  version 1.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36037/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2009/Jul/418" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/cve/CVE-2010-2062" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_vlc_media_player_detect_lin.sc" );
	script_mandatory_keys( "VLCPlayer/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vlcVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vlcVer, test_version: "1.0.1" )){
	report = report_fixed_ver( installed_version: vlcVer, fixed_version: "1.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}

