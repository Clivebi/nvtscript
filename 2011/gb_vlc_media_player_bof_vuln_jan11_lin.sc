if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801727" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)" );
	script_cve_id( "CVE-2011-0021" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "VLC Media Player 'CDG decoder' multiple buffer overflow vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0185" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/01/20/3" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_vlc_media_player_detect_lin.sc" );
	script_mandatory_keys( "VLCPlayer/Lin/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to crash the affected
  application, or execute arbitrary code by convincing a user to open a
  malicious CD+G (CD+Graphics) media file or visit a specially crafted web
  page." );
	script_tag( name: "affected", value: "VLC media player version prior to 1.1.6 on Linux" );
	script_tag( name: "insight", value: "The flaws are due to an array indexing errors in the 'DecodeTileBlock()'
  and 'DecodeScroll()' [modules/codec/cdg.c] functions within the CDG decoder
  module when processing malformed data." );
	script_tag( name: "solution", value: "Upgrade to the VLC media player version 1.1.6 or later." );
	script_tag( name: "summary", value: "The host is installed with VLC Media Player and is prone multiple
  buffer overflow vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vlcVer = get_kb_item( "VLCPlayer/Lin/Ver" );
if(!vlcVer){
	exit( 0 );
}
if(version_is_less( version: vlcVer, test_version: "1.1.6" )){
	report = report_fixed_ver( installed_version: vlcVer, fixed_version: "1.1.6" );
	security_message( port: 0, data: report );
}

