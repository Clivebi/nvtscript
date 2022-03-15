if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901019" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2139" );
	script_bugtraq_id( 36291 );
	script_name( "OpenOffice EMF File Parser Remote Command Execution Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2009/dsa-1880" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_openoffice_detect_lin.sc" );
	script_mandatory_keys( "OpenOffice/Linux/Ver" );
	script_tag( name: "impact", value: "Successful remote exploitation could result in arbitrary code execution." );
	script_tag( name: "affected", value: "OpenOffice Version 2.x and 3.x on windows." );
	script_tag( name: "insight", value: "An Unspecified error occurs in the parser of EMF files when parsing certain
  crafted EMF files." );
	script_tag( name: "solution", value: "Upgrade to OpenOffice Version 3.1.1 or later." );
	script_tag( name: "summary", value: "The host has OpenOffice installed and is prone to Remote Command
  Execution Vulnerability" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
openVer = get_kb_item( "OpenOffice/Linux/Ver" );
if(!openVer){
	exit( 0 );
}
if(version_in_range( version: openVer, test_version: "2.0", test_version2: "3.1.1" )){
	report = report_fixed_ver( installed_version: openVer, vulnerable_range: "2.0 - 3.1.1" );
	security_message( port: 0, data: report );
}

