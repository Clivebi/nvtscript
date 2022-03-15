CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803954" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2013-4388" );
	script_bugtraq_id( 62724 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-10-22 19:22:32 +0530 (Tue, 22 Oct 2013)" );
	script_name( "VLC Media Player mp4a Denial of Service Vulnerability (Windows)" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to overflow buffer, cause denial
  of service." );
	script_tag( name: "affected", value: "VLC media player version 2.0.7 and prior on Windows." );
	script_tag( name: "insight", value: "A flaw exists in mpeg4audio.c file, which to perform adequate boundary checks
  on user-supplied input." );
	script_tag( name: "solution", value: "Upgrade to VLC media player version 2.0.8 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "This host is installed with VLC Media Player and is prone to denial of service
  vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1029120" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2013/10/01/2" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
vlcVer = get_app_version( cpe: CPE );
if(!vlcVer){
	exit( 0 );
}
if(version_is_less_equal( version: vlcVer, test_version: "2.0.7" )){
	report = report_fixed_ver( installed_version: vlcVer, vulnerable_range: "Less than or equal to 2.0.7" );
	security_message( port: 0, data: report );
	exit( 0 );
}

