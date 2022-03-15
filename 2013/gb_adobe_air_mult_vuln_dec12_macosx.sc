if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803455" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678" );
	script_bugtraq_id( 56892, 56896, 56898 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-03-28 18:17:03 +0530 (Thu, 28 Mar 2013)" );
	script_name( "Adobe Air Multiple Vulnerabilities - December12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51560" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027854" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2755801" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-27.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Air/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or denial of service." );
	script_tag( name: "affected", value: "Adobe AIR version 3.5.0.600 and earlier on Mac OS X" );
	script_tag( name: "insight", value: "Multiple unspecified errors and integer overflow exists that could lead to
  code execution." );
	script_tag( name: "solution", value: "Update to Adobe Air version 3.5.0.890 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Adobe Air and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
airVer = get_kb_item( "Adobe/Air/MacOSX/Version" );
if(airVer){
	if(version_is_less( version: airVer, test_version: "3.5.0.890" )){
		report = report_fixed_ver( installed_version: airVer, fixed_version: "3.5.0.890" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

