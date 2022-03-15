if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800222" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-5862" );
	script_bugtraq_id( 32928 );
	script_name( "webcamXP URL Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33257" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7521" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_webcamxp_detect.sc" );
	script_mandatory_keys( "WebcamXP/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute malicious URL into
  the web browser in the attacking machine and can get sensitive information
  about the application or about the remote system." );
	script_tag( name: "affected", value: "Darkwet, webcamXP version 5.3.2.410 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is due to improper handling of URL-encoded forward-slashes i.e, ../
  which causes execution of malicious URI into the context of the application." );
	script_tag( name: "solution", value: "Upgrade to webcamXP version 5.5.0.8 or later" );
	script_tag( name: "summary", value: "This host is installed with webcamXP and is prone to Directory
  Traversal Vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.webcamxp.com" );
	exit( 0 );
}
require("version_func.inc.sc");
wcVer = get_kb_item( "WebcamXP/Version" );
if(!wcVer){
	exit( 0 );
}
if(version_is_less_equal( version: wcVer, test_version: "5.3.2.410" )){
	report = report_fixed_ver( installed_version: wcVer, vulnerable_range: "Less than or equal to 5.3.2.410" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

