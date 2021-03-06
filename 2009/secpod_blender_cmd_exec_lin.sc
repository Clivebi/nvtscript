if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900252" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3850" );
	script_bugtraq_id( 36838 );
	script_name( "Blender .blend File Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/content/blender-scripting-injection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_blender_detect_lin.sc" );
	script_mandatory_keys( "Blender/Lin/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
commands by sending a specially crafted .blend file that contains Python
statements in the onLoad action of a ScriptLink SDNA." );
	script_tag( name: "affected", value: "Blender 2.49b, 2.40, 2.35a, 2.34 and prior." );
	script_tag( name: "insight", value: "This flaw is generated because Blender allows .blend project
files to be modified to execute arbitrary commands without user intervention
by design." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with blender and is prone to Remote
Command Execution Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("version_func.inc.sc");
blendVer = get_kb_item( "Blender/Lin/Ver" );
if(!blendVer){
	exit( 0 );
}
if(version_is_equal( version: blendVer, test_version: "2.49.2" ) || version_is_equal( version: blendVer, test_version: "2.40" ) || version_is_equal( version: blendVer, test_version: "2.35.1" ) || version_is_less_equal( version: blendVer, test_version: "2.34" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

