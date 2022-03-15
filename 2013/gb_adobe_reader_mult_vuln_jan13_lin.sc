CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803212" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2012-1530", "CVE-2013-0601", "CVE-2013-0602", "CVE-2013-0603", "CVE-2013-0604", "CVE-2013-0605", "CVE-2013-0606", "CVE-2013-0607", "CVE-2013-0608", "CVE-2013-0609", "CVE-2013-0610", "CVE-2013-0611", "CVE-2013-0612", "CVE-2013-0613", "CVE-2013-0614", "CVE-2013-0615", "CVE-2013-0616", "CVE-2013-0617", "CVE-2013-0618", "CVE-2013-0619", "CVE-2013-0620", "CVE-2013-0621", "CVE-2013-0622", "CVE-2013-0623", "CVE-2013-0624", "CVE-2013-0626", "CVE-2013-0627", "CVE-2013-1376" );
	script_bugtraq_id( 57264, 57272, 57289, 57282, 57283, 57273, 57263, 57290, 57291, 57286, 57284, 57292, 57265, 57287, 57293, 57268, 57274, 57269, 57294, 57275, 57276, 57270, 57295, 57277, 57296, 57285, 57297, 65275 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-01-21 13:16:59 +0530 (Mon, 21 Jan 2013)" );
	script_name( "Adobe Reader Multiple Vulnerabilities - Jan 13 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
restrictions, execute arbitrary code in the context of the affected
application or cause a denial of service." );
	script_tag( name: "affected", value: "Adobe Reader versions 9.x to 9.5.2 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.5.3 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51791" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027952" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-02.html" );
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
	if(version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.5.2" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "9.0 - 9.5.2" );
		security_message( port: 0, data: report );
	}
}

