if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802801" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0928" );
	script_bugtraq_id( 51890 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-02-21 15:19:43 +0530 (Tue, 21 Feb 2012)" );
	script_name( "RealNetworks RealPlayer Atrac Sample Decoding Remote Code Execution Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026643" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51890" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/02062012_player/en/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary
  code." );
	script_tag( name: "affected", value: "RealPlayer versions 11.x and 14.x

  RealPlayer SP versions 1.0 through 1.1.5 (12.0.0.879) on Windows" );
	script_tag( name: "insight", value: "The flaw is due to an improper decoding of samples by ATRAC codec,
  which allows remote attackers to execute arbitrary code via a crafted ATRAC
  audio file." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer version 15.2.71 or later." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to a remote
  code execution vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/Win/Ver" );
if(isnull( rpVer )){
	exit( 0 );
}
if(( IsMatchRegexp( rpVer, "^11\\.*" ) ) || ( IsMatchRegexp( rpVer, "^12\\.0\\.1\\.*" ) ) || version_in_range( version: rpVer, test_version: "12.0.0", test_version2: "12.0.0.879" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

