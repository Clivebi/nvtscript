if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903389" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-3211", "CVE-2013-3210" );
	script_bugtraq_id( 58864, 59317 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-05-02 11:20:49 +0530 (Thu, 02 May 2013)" );
	script_name( "Opera Multiple Vulnerabilities-01 May13 (Linux)" );
	script_xref( name: "URL", value: "http://www.opera.com/security/advisory/1047" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/unified/1215" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_opera_detection_linux_900037.sc" );
	script_mandatory_keys( "Opera/Linux/Version" );
	script_tag( name: "impact", value: "Successful exploitation could led to user's accounts being compromised or
  disclose sensitive information that may aid in launching further attacks." );
	script_tag( name: "affected", value: "Opera version before 12.15 on Linux" );
	script_tag( name: "insight", value: "- Unspecified error related to 'moderately severe issue'.

  - Does not properly block top-level domains in Set-Cookie headers." );
	script_tag( name: "solution", value: "Upgrade to Opera version 12.15 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Linux/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "12.15" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "12.15" );
	security_message( port: 0, data: report );
	exit( 0 );
}

