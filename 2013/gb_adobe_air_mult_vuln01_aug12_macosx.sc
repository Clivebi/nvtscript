if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803489" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-4163", "CVE-2012-4164", "CVE-2012-4165", "CVE-2012-4166", "CVE-2012-4167", "CVE-2012-4168", "CVE-2012-4171", "CVE-2012-5054" );
	script_bugtraq_id( 55136, 55365 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-08-24 11:31:28 +0530 (Fri, 24 Aug 2012)" );
	script_name( "Adobe Air Multiple Vulnerabilities -01 August 12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50354" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Air/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe AIR version 3.3.0.3670 and earlier on Mac OS X" );
	script_tag( name: "insight", value: "The flaws are due to memory corruption, integer overflow errors that
  could lead to code execution." );
	script_tag( name: "solution", value: "Update to Adobe Air version 3.4.0.2540 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Air and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Adobe/Air/MacOSX/Version" );
if(vers){
	if(version_is_less_equal( version: vers, test_version: "3.3.0.3670" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 3.3.0.3670" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

