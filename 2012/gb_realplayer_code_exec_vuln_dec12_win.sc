if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803088" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-5690", "CVE-2012-5691" );
	script_bugtraq_id( 56956 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-12-25 10:46:45 +0530 (Tue, 25 Dec 2012)" );
	script_name( "RealNetworks RealPlayer Code Execution Vulnerabilities - Dec12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51589" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027893" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/12142012_player/en" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  on the system or cause the application to crash." );
	script_tag( name: "affected", value: "RealPlayer versions 15.0.6.14 and prior on Windows
  RealPlayer SP versions 1.0 through 1.1.5 (12.0.0.879) on Windows" );
	script_tag( name: "insight", value: "Multiple errors are caused when handling

  - RealAudio files may result in dereferencing an invalid pointer.

  - RealMedia files can be exploited to cause a buffer overflow." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer version 16.0.0.282 or later." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to multiple
  code execution vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/Win/Ver" );
if(!rpVer){
	exit( 0 );
}
if(version_in_range( version: rpVer, test_version: "11.0", test_version2: "12.0.0.879" ) || version_in_range( version: rpVer, test_version: "12.0.1", test_version2: "15.0.6.14" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

