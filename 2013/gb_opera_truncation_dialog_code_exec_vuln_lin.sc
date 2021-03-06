if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803148" );
	script_version( "$Revision: 11865 $" );
	script_cve_id( "CVE-2012-6460" );
	script_bugtraq_id( 55301 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-01-07 16:22:46 +0530 (Mon, 07 Jan 2013)" );
	script_name( "Opera Truncated Dialogs Code Execution Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1028/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/unified/1202/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_opera_detection_linux_900037.sc" );
	script_mandatory_keys( "Opera/Linux/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute the code and perform
  other unwanted actions." );
	script_tag( name: "affected", value: "Opera version before 11.67 and 12.x before 12.02 on Linux" );
	script_tag( name: "insight", value: "An error in handling of truncated dialogs, can be used to cause the user
  to download and run executables unexpectedly or perform other unwanted
  actions." );
	script_tag( name: "solution", value: "Upgrade to Opera version 11.67 or 12.02" );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to code execution
  vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Linux/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "11.67" ) || version_in_range( version: operaVer, test_version: "12.0", test_version2: "12.01" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

