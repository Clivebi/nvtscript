CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801782" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)" );
	script_cve_id( "CVE-2011-1087" );
	script_bugtraq_id( 38569 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "VLC Media Player 'Bookmark Creation' Buffer Overflow Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38853" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial-of-service
  conditions." );
	script_tag( name: "affected", value: "VLC media player version prior to 1.0.6 on Windows" );
	script_tag( name: "insight", value: "The flaw is due to a race condition error when creating bookmarks and
  can be exploited to corrupt memory by tricking a user into creating a
  bookmark while playing a specially crafted file." );
	script_tag( name: "solution", value: "Upgrade to the VLC media player version 1.0.6 or later." );
	script_tag( name: "summary", value: "The host is installed with VLC Media Player and is prone buffer
  overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "1.0", test_version2: "1.0.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.6", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

