if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902707" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)" );
	script_cve_id( "CVE-2011-2588" );
	script_bugtraq_id( 48664 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "VLC Media Player '.AVI' File BOF Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45066" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68532" );
	script_xref( name: "URL", value: "http://www.videolan.org/security/sa1106.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_vlc_media_player_detect_lin.sc" );
	script_mandatory_keys( "VLCPlayer/Lin/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial-of-service
  conditions." );
	script_tag( name: "affected", value: "VLC media player version prior to 1.1.11 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to an integer underflow error when parsing the 'strf'
  chunk within AVI files can be exploited to cause a heap-based buffer
  overflow." );
	script_tag( name: "solution", value: "Upgrade to the VLC media player version 1.1.11 or later." );
	script_tag( name: "summary", value: "The host is installed with VLC Media Player and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vlcVer = get_kb_item( "VLCPlayer/Lin/Ver" );
if(!vlcVer){
	exit( 0 );
}
if(version_is_less( version: vlcVer, test_version: "1.1.11" )){
	report = report_fixed_ver( installed_version: vlcVer, fixed_version: "1.1.11" );
	security_message( port: 0, data: report );
}

