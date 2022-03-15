CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800077" );
	script_version( "$Revision: 12666 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-05 13:36:06 +0100 (Wed, 05 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2008-12-09 13:27:23 +0100 (Tue, 09 Dec 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5276" );
	script_bugtraq_id( 32545 );
	script_name( "VLC Media Player Buffer Overflow Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_vlc_media_player_detect_lin.sc" );
	script_mandatory_keys( "VLCPlayer/Lin/Ver" );
	script_xref( name: "URL", value: "http://www.videolan.org/security/sa0811.html" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2008/3287" );
	script_xref( name: "URL", value: "http://www.trapkit.de/advisories/TKADV2008-013.txt" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary
  code by tricking a user into opening a specially crafted .rm file to
  crash an affected application." );
	script_tag( name: "affected", value: "VLC media player 0.9.0 through 0.9.7 on Linux (Any)." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error while parsing ReadRealIndex
  function in real.c in the Real demuxer plugin." );
	script_tag( name: "solution", value: "Upgrade to VLC media player 0.9.8." );
	script_tag( name: "summary", value: "This host is installed with VLC Media Player and is prone to
  Buffer Overflow Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
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
if(version_in_range( version: vers, test_version: "0.9.0", test_version2: "0.9.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.8", install_path: path );
	security_message( port: 0, data: report );
}
exit( 0 );

