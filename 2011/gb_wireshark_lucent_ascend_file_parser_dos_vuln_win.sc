if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802308" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)" );
	script_cve_id( "CVE-2011-2597" );
	script_bugtraq_id( 48506 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Wireshark Lucent/Ascend File Parser Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45086" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68335" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2011-09.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_family( "Denial of Service" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to cause the application to enter
  into an infinite loop and crash it." );
	script_tag( name: "affected", value: "Wireshark version 1.2.0 to 1.2.17, 1.4.0 to 1.4.7 and 1.6.0" );
	script_tag( name: "insight", value: "The flaw is due to an error in Lucent/Ascend file parser when
  processing malicious packets." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.2.18 or later" );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial of
  service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wireVer = get_kb_item( "Wireshark/Win/Ver" );
if(!wireVer){
	exit( 0 );
}
if(version_in_range( version: wireVer, test_version: "1.2.0", test_version2: "1.2.17" ) || version_in_range( version: wireVer, test_version: "1.4.0", test_version2: "1.4.7" ) || version_is_equal( version: wireVer, test_version: "1.6.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

