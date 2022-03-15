if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801673" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)" );
	script_bugtraq_id( 45411 );
	script_cve_id( "CVE-2010-4376", "CVE-2010-4397" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "RealNetworks RealPlayer Multiple Vulnerabilities (Windows) - Dec10" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38550/" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/12102010_player/en/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service." );
	script_tag( name: "affected", value: "RealPlayer SP 1.0 to 1.1.1 (12.x)
  RealNetworks RealPlayer SP 11.0 to 11.1 on Windows platform." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Heap-based buffer overflow error when parsing a large Screen Width value
    in the Screen Descriptor header of a GIF87a file in an RTSP stream.

  - An integer overflow in the pnen3260.dll module allows remote attackers to
    execute arbitrary code via a crafted TIT2 atom in an AAC file." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer 14.0.1.609 (Build 12.0.1.609) or later." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/Win/Ver" );
if(isnull( rpVer )){
	exit( 0 );
}
if(version_in_range( version: rpVer, test_version: "11.0.0", test_version2: "11.0.0.674" ) || version_in_range( version: rpVer, test_version: "12.0.0", test_version2: "12.0.0.614" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

