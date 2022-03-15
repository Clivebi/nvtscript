CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803417" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-0640", "CVE-2013-0641" );
	script_bugtraq_id( 57931, 57947 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-02-19 19:06:59 +0530 (Tue, 19 Feb 2013)" );
	script_name( "Adobe Reader Multiple Unspecified Vulnerabilities -01 Feb13 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple unspecified
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code or cause
a denial of service via a crafted PDF document." );
	script_tag( name: "affected", value: "Adobe Reader Version 9.x prior to 9.5.4 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.5.4 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52196" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa13-02.html" );
	script_xref( name: "URL", value: "http://blogs.adobe.com/psirt/2013/02/adobe-reader-and-acrobat-vulnerability-report.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( readerVer, "^9" )){
	if(version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.5.3" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "9.0 - 9.5.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

