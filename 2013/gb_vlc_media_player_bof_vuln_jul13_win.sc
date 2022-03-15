CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803698" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-1954" );
	script_bugtraq_id( 57333 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-16 13:35:48 +0530 (Tue, 16 Jul 2013)" );
	script_name( "VLC Media Player Buffer Overflow Vulnerability - July 13 (Windows)" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code or
cause denial of service condition in the context of affected application via
crafted ASF file." );
	script_tag( name: "affected", value: "VLC media player version 2.0.5 and prior on Windows" );
	script_tag( name: "insight", value: "Flaw due to error in 'DemuxPacket()' function in the ASF Demuxer component
(modules/demux/asf/asf.c) when parsing ASF files." );
	script_tag( name: "solution", value: "Upgrade to VLC media player version 2.0.6 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "This host is installed with VLC Media Player and is prone to
buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51995" );
	script_xref( name: "URL", value: "http://www.videolan.org/security/sa1302.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "2.0.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.0.6", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

