if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801432" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)" );
	script_cve_id( "CVE-2010-2995" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Wireshark Multiple Vulnerabilities (win)" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2010-08.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.2.10.html" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a denial of
  service, execution of arbitrary code." );
	script_tag( name: "affected", value: "Wireshark version 1.2.0 to 1.2.9
  Wireshark version 0.10.8 to 1.0.14" );
	script_tag( name: "insight", value: "Multiple flaws are due to error in 'sigcomp-udvm.c' and an
  off-by-one error, which could be exploited to execute arbitrary code." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.0.15 or 1.2.10 or later." );
	script_tag( name: "summary", value: "The host is installed Wireshark and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "0.10.8", test_version2: "1.0.14" ) || version_in_range( version: wiresharkVer, test_version: "1.2.0", test_version2: "1.2.9" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

