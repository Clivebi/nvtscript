if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902239" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)" );
	script_cve_id( "CVE-2010-3133" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Wireshark File Opening Insecure Library Loading Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41064" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14721/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2165" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attackers to execute
arbitrary code and conduct DLL hijacking attacks." );
	script_tag( name: "affected", value: "Wireshark version 1.2.10 and prior on windows." );
	script_tag( name: "insight", value: "The flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers to
execute arbitrary code by tricking a user into opening a file from a network share." );
	script_tag( name: "solution", value: "Upgrade to version 1.2.11 or higher." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to insecure library
loading vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_is_less_equal( version: sharkVer, test_version: "1.2.10" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "Less than or equal to 1.2.10" );
	security_message( port: 0, data: report );
}

