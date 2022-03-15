CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902704" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)" );
	script_cve_id( "CVE-2011-2587" );
	script_bugtraq_id( 48664 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "VLC Media Player '.RM' File BOF Vulnerability (Windows)" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial-of-service
  conditions." );
	script_tag( name: "affected", value: "VLC media player version 1.1.0 to 1.1.10 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to missing input validation when allocating memory
  using certain values from a RealAudio data block within RealMedia (RM)
  files." );
	script_tag( name: "solution", value: "Upgrade to the VLC media player version 1.1.11 or later." );
	script_tag( name: "summary", value: "The host is installed with VLC Media Player and is prone to
  buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45066" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68531" );
	script_xref( name: "URL", value: "http://www.videolan.org/security/sa1105.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "1.1.0", test_version2: "1.1.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.1.11", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

