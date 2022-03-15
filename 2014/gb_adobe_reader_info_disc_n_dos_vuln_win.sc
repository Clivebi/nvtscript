CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804398" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2005-0035", "CVE-2005-0492" );
	script_bugtraq_id( 12989 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-15 11:58:59 +0530 (Tue, 15 Apr 2014)" );
	script_name( "Adobe Reader Information Disclosure & Denial of Service Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to information disclosure
and denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws exist due to:

  - An unspecified error in the 'LoadFile' method.

  - An unspecified error within the processing of PDF documents containing a
negative root page node 'Count' value." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct denial of service
attack and the disclosure of sensitive information." );
	script_tag( name: "affected", value: "Adobe Reader version 7.0 and earlier on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 7.0.5 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/14813" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/techdocs/331465.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/techdocs/331468.html" );
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
if(version_is_less_equal( version: vers, test_version: "7.0" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 7.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

