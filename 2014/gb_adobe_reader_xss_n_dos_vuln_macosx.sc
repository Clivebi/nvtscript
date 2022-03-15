CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804396" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2007-0045", "CVE-2007-0048" );
	script_bugtraq_id( 21858 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-15 11:40:57 +0530 (Tue, 15 Apr 2014)" );
	script_name( "Adobe Reader Cross-Site Scripting & Denial of Service Vulnerabilities (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to cross site scripting
and denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws exist due to:

  - the browser plug-in does not validate user supplied input to the hosted PDF
file before returning the input to the user.

  - some unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause memory corruption,
conduct denial of service attack and the execution of arbitrary script code in
a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Adobe Reader version 9.x before 9.2, 8.x before 8.1.7, 7.x before 7.1.4, 7.0.8
and earlier on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.2 or 8.1.7 or 7.1.4 or 7.0.9 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36983" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1017469" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb07-01.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb09-15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Reader/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "7.0.8" ) || version_in_range( version: vers, test_version: "7.1.0", test_version2: "7.1.3" ) || version_in_range( version: vers, test_version: "8.0", test_version2: "8.1.6" ) || version_in_range( version: vers, test_version: "9.0", test_version2: "9.1.3" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

