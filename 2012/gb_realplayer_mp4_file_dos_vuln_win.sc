if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802826" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_bugtraq_id( 53555 );
	script_cve_id( "CVE-2012-1904", "CVE-2012-2406", "CVE-2012-2411" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-04-02 16:18:38 +0530 (Mon, 02 Apr 2012)" );
	script_name( "RealNetworks RealPlayer MP4 File Handling Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49193" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74316" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/75647" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/75648" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/422383.php" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/05152012_player/en/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111162/RealPlayer-1.1.4-Memory-Corruption.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to execute arbitrary
  code, cause buffer overflow or cause the application to crash, creating a
  denial of service condition." );
	script_tag( name: "affected", value: "RealPlayer versions before 15.0.4.53
  RealPlayer SP versions 1.0 through 1.1.5 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to

  - An error the in 'mp4fformat.dll' in the QuickTime File Format plugin. This
    can be exploited to cause a crash by sending a crafted MP4 file.

  - An error within the parsing of RealMedia ASMRuleBook.

  - An error within the RealJukebox Media parser, which allows to cause a
    buffer overflow." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer version 15.0.4.53 or later." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to denial of
  service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/Win/Ver" );
if(isnull( rpVer )){
	exit( 0 );
}
if(( IsMatchRegexp( rpVer, "^12\\.0\\.1\\.*" ) ) || version_is_less_equal( version: rpVer, test_version: "12.0.0.879" ) || version_in_range( version: rpVer, test_version: "15.0.0", test_version2: "15.0.3.37" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

