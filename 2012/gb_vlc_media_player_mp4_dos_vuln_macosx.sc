if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802921" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-2396" );
	script_bugtraq_id( 53535, 53169 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-07-25 13:33:36 +0530 (Wed, 25 Jul 2012)" );
	script_name( "VLC Media Player 'MP4' Denial of Service Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49159" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/75038" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18757" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111991/VLC-2.0.1-Division-By-Zero.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_vlc_media_player_detect_macosx.sc" );
	script_mandatory_keys( "VLC/Media/Player/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to crash the affected
application, denying service to legitimate users." );
	script_tag( name: "affected", value: "VLC media player version 2.0.1 on Mac OS X." );
	script_tag( name: "insight", value: "A division by zero error exists when handling MP4 files, which
can be exploited to cause a crash." );
	script_tag( name: "solution", value: "Update to version 1.7.2 or later." );
	script_tag( name: "summary", value: "This host is installed with VLC Media Player and is prone to
denial of service vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vlcVer = get_kb_item( "VLC/Media/Player/MacOSX/Version" );
if(!vlcVer){
	exit( 0 );
}
if(version_is_equal( version: vlcVer, test_version: "2.0.1" )){
	report = report_fixed_ver( installed_version: vlcVer, vulnerable_range: "Equal to 2.0.1" );
	security_message( port: 0, data: report );
}
