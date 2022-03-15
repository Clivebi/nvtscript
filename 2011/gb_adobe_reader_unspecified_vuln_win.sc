CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802165" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_cve_id( "CVE-2011-1353" );
	script_bugtraq_id( 49586 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)" );
	script_name( "Adobe Reader Unspecified Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to unspecified
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An unspecified flaw is present in the application which can be exploited
through unknown attack vectors." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to gain privileges via unknown
vectors." );
	script_tag( name: "affected", value: "Adobe Reader version 10.x through 10.1 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 10.1.1 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-24.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Reader/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( readerVer, "^10" )){
	if(version_in_range( version: readerVer, test_version: "10.0", test_version2: "10.1" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "10.0 - 10.1" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

