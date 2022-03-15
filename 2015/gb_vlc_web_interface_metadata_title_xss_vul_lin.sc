CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806753" );
	script_version( "2019-07-05T09:29:25+0000" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 09:29:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-12-01 10:52:46 +0530 (Tue, 01 Dec 2015)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_name( "VLC Media Player Web Interface Cross Site Scripting Vulnerability Dec15 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with VLC media player
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to insufficient
  sanitization of metadata that is getting executed." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the serve." );
	script_tag( name: "affected", value: "VideoLAN VLC media player 2.2.1 on Linux." );
	script_tag( name: "solution", value: "Upgrade to VideoLAN VLC media player version
  2.2.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/38706" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_vlc_media_player_detect_lin.sc" );
	script_mandatory_keys( "VLCPlayer/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vlcVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: vlcVer, test_version: "2.2.1" )){
	report = "Installed version: " + vlcVer + "\n" + "Fixed version:     2.2.2";
	security_message( data: report );
	exit( 0 );
}

