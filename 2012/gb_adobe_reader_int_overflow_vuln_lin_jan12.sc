CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802421" );
	script_version( "2020-10-01T08:15:04+0000" );
	script_cve_id( "CVE-2011-4374" );
	script_bugtraq_id( 51557 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-01 08:15:04 +0000 (Thu, 01 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-01-23 15:55:01 +0530 (Mon, 23 Jan 2012)" );
	script_name( "Adobe Reader Integer Overflow Vulnerability - Jan 12 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to integer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an integer overflow error, which allow the attackers to
execute arbitrary code via unspecified vectors." );
	script_tag( name: "impact", value: "Successful exploitation will allow the attackers to execute arbitrary code
via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Reader version 9.x before 9.4.6 on Linux." );
	script_tag( name: "solution", value: "Upgrade Adobe Reader to 9.4.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-24.html" );
	script_xref( name: "URL", value: "http://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-4374.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
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
	if(version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.4.5" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "9.0 - 9.4.5" );
		security_message( port: 0, data: report );
	}
}

