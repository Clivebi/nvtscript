if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802653" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-3561" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-06-21 17:17:17 +0530 (Thu, 21 Jun 2012)" );
	script_name( "Opera URL Processing Arbitrary Code Execution Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027066" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1016/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/mac/1164/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_macosx.sc" );
	script_mandatory_keys( "Opera/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service." );
	script_tag( name: "affected", value: "Opera version prior to 11.64 on Mac OS X" );
	script_tag( name: "insight", value: "The flaw is due to improper allocation of memory for URL strings,
  which allows remote attackers to execute arbitrary code or cause a denial
  of service (memory corruption and application crash) via a crafted string." );
	script_tag( name: "solution", value: "Upgrade to Opera version 11.64 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to code execution
  vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/MacOSX/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "11.64" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "11.64" );
	security_message( port: 0, data: report );
}

