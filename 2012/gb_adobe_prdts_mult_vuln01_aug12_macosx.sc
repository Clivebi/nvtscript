if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802953" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2012-4163", "CVE-2012-4164", "CVE-2012-4165", "CVE-2012-4166", "CVE-2012-4167", "CVE-2012-4168", "CVE-2012-4171", "CVE-2012-5054" );
	script_bugtraq_id( 55136, 55365 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-08-24 11:31:28 +0530 (Fri, 24 Aug 2012)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities -01 August 12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50354" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.23, 11.x before 11.4.402.265 on Mac OS X" );
	script_tag( name: "insight", value: "The flaws are due to memory corruption, integer overflow errors that
  could lead to code execution." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 10.3.183.23 or 11.4.402.265 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
playerVer = get_kb_item( "Adobe/Flash/Player/MacOSX/Version" );
if(playerVer){
	if(version_is_less( version: playerVer, test_version: "10.3.183.23" ) || version_in_range( version: playerVer, test_version: "11.0", test_version2: "11.3.300.271" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

