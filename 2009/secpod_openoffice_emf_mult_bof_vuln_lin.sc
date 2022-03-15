if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900955" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2140" );
	script_name( "OpenOffice EMF Files Multiple Buffer Overflow Vulnerabilities (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_openoffice_detect_lin.sc" );
	script_mandatory_keys( "OpenOffice/Linux/Ver" );
	script_tag( name: "impact", value: "Successful remote exploitation could result in arbitrary code execution." );
	script_tag( name: "affected", value: "OpenOffice 2.x and 3.x before 3.0.1 on Linux." );
	script_tag( name: "insight", value: "Multiple flaws exist due to a buffer overflow error in cppcanvas/source/
  mtfrenderer/emfplus.cxx' when processing crafted EMF+ files." );
	script_tag( name: "solution", value: "Upgrade to OpenOffice 3.0.1 or later." );
	script_tag( name: "summary", value: "The host has OpenOffice installed and is prone to Multiple Buffer
  Overflow vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://marc.info/?l=oss-security&m=125258116800739&w=2" );
	script_xref( name: "URL", value: "http://marc.info/?l=oss-security&m=125265261125765&w=2" );
	exit( 0 );
}
require("version_func.inc.sc");
openVer = get_kb_item( "OpenOffice/Linux/Ver" );
if(!openVer){
	exit( 0 );
}
if(IsMatchRegexp( openVer, "^[23]\\." )){
	if(version_is_less( version: openVer, test_version: "3.0.1" )){
		report = report_fixed_ver( installed_version: openVer, fixed_version: "3.0.1" );
		security_message( port: 0, data: report );
	}
}

