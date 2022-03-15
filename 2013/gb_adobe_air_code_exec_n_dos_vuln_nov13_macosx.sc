CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804149" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-5329", "CVE-2013-5330" );
	script_bugtraq_id( 63680, 63680 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-11-19 15:46:28 +0530 (Tue, 19 Nov 2013)" );
	script_name( "Adobe AIR Code Execution and DoS Vulnerabilities Nov13 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe AIR and is prone to remote code execution and
denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Adobe AIR version 3.9.0.1210 or later." );
	script_tag( name: "insight", value: "Flaws are due to multiple unspecified errors." );
	script_tag( name: "affected", value: "Adobe AIR before 3.9.0.1210 on Mac OS X" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code, cause
denial of service (memory corruption) and compromise a user's system." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55527" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-26.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Air/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "3.9.0.1210" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.9.0.1210" );
	security_message( port: 0, data: report );
	exit( 0 );
}

