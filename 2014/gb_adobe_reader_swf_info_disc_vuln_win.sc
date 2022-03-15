CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804262" );
	script_version( "2021-08-13T07:21:38+0000" );
	script_cve_id( "CVE-2004-1598" );
	script_bugtraq_id( 11386 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 07:21:38 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-16 10:27:12 +0530 (Wed, 16 Apr 2014)" );
	script_name( "Adobe Reader 'SWF' Information Disclosure Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to information
disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to the error in processing of embedded Macromedia Flash (.swf)
files within PDF files." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain knowledge of potentially
sensitive information." );
	script_tag( name: "affected", value: "Adobe Reader version 6.x before 6.0.3 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader 6.0.3 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/12809" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1011651" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/17694" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Reader/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "6.0 - 6.0.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}

