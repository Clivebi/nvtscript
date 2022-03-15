if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802249" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)" );
	script_bugtraq_id( 49528 );
	script_cve_id( "CVE-2011-3360" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Wireshark Lua Script File Arbitrary Code Execution Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2011-15.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6136" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attacker to execute arbitrary Lua
  script in the context of the affected application." );
	script_tag( name: "affected", value: "Wireshark versions 1.4.x before 1.4.9 and 1.6.x before 1.6.2." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error related to Lua scripts, which
  allows local users to gain privileges via a Trojan horse Lua script in an
  unspecified directory." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.4.9, 1.6.2 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to code
  execution vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.6.0", test_version2: "1.6.1" ) || version_in_range( version: sharkVer, test_version: "1.4.0", test_version2: "1.4.8" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

