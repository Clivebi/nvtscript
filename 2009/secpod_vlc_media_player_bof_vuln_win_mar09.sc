CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900530" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1045" );
	script_bugtraq_id( 34126 );
	script_name( "VLC Media Player Stack Overflow Vulnerability (Win-Mar09)" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8213" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49249" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/03/17/4" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation allows the attacker to execute arbitrary codes
  with escalated privileges and cause overflow in stack." );
	script_tag( name: "affected", value: "VLC media player 0.9.8a and prior on Windows." );
	script_tag( name: "insight", value: "This flaw is due to improper boundary checking in status.xml in the web
  interface by an overly long request." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to VLC media player version 1.0 or later." );
	script_tag( name: "summary", value: "This host is installed with VLC Media Player and is prone to
  Stack Overflow Vulnerability." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "0.9.8a" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

