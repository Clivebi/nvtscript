CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802544" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_cve_id( "CVE-2011-2462", "CVE-2011-4369" );
	script_bugtraq_id( 50922, 51092 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-12-09 12:52:04 +0530 (Fri, 09 Dec 2011)" );
	script_name( "Adobe Reader 'U3D' Component Memory Corruption Vulnerability - Linux" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to memory corruption
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error while handling U3D data." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code in the
context of the affected application or cause a denial of service." );
	script_tag( name: "affected", value: "Adobe Reader versions 9.x through 9.4.6 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.4.7 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47133/" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa11-04.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
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
	if(version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.4.6" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "9.0 - 9.4.6" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

