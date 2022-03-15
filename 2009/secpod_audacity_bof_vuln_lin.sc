if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900307" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0490" );
	script_bugtraq_id( 33090 );
	script_name( "Audacity Buffer Overflow Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33356" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7634" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_audacity_detect_lin.sc" );
	script_mandatory_keys( "Audacity/Linux/Ver" );
	script_tag( name: "impact", value: "Attacker may leverage this issue by executing arbitrary script code on
  the affected application, and can cause denial of service." );
	script_tag( name: "affected", value: "Audacity version prior to 1.3.6 on Linux." );
	script_tag( name: "insight", value: "Error in the String_parse::get_nonspace_quoted function in
  lib-src/allegro/strparse.cpp file that fails to validate user input data." );
	script_tag( name: "solution", value: "Upgrade to version 1.3.6 or later." );
	script_tag( name: "summary", value: "This host has Audacity installed and is prone to Buffer Overflow
  vulnerability." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
audacityVer = get_kb_item( "Audacity/Linux/Ver" );
if(!audacityVer){
	exit( 0 );
}
if(version_is_less( version: audacityVer, test_version: "1.3.6" )){
	report = report_fixed_ver( installed_version: audacityVer, fixed_version: "1.3.6" );
	security_message( port: 0, data: report );
}

