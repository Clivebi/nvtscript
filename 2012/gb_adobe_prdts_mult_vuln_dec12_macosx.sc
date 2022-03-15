if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803075" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_cve_id( "CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678" );
	script_bugtraq_id( 56892, 56896, 56898 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-14 15:17:00 +0530 (Fri, 14 Dec 2012)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities - December12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51560" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027854" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2755801" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-27.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or denial of service." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.48, 11.x before 11.5.502.136 on Mac OS X" );
	script_tag( name: "insight", value: "Multiple unspecified errors and integer overflow exists that could lead to
  code execution." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 10.3.183.48 or 11.5.502.136 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
playerVer = get_kb_item( "Adobe/Flash/Player/MacOSX/Version" );
if(playerVer){
	if(version_is_less( version: playerVer, test_version: "10.3.183.48" ) || version_in_range( version: playerVer, test_version: "11.0", test_version2: "11.5.502.135" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

