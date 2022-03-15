CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902406" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)" );
	script_cve_id( "CVE-2010-3275", "CVE-2010-3276" );
	script_bugtraq_id( 47012 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "VLC Media Player AMV and NSV Data Processing Memory Corruption vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43826" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025250" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/66259" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0759" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious file or visiting a specially crafted
  web page." );
	script_tag( name: "affected", value: "VLC media player version prior to 1.1.8 on Windows." );
	script_tag( name: "insight", value: "The flaw is caused by a memory corruption error in the 'libdirectx' plugin when
  processing malformed NSV or AMV data, which allows the attackers to execute
  arbitrary code." );
	script_tag( name: "solution", value: "Upgrade to the VLC media player version 1.1.8 or later." );
	script_tag( name: "summary", value: "The host is installed with VLC Media Player and is prone to memory
  corruption vulnerability." );
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
if(version_is_less( version: vers, test_version: "1.1.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.1.8", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

