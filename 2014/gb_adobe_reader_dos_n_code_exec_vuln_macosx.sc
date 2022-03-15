CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804263" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2010-3623", "CVE-2010-3631", "CVE-2010-3624" );
	script_bugtraq_id( 43731, 43733, 43736 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-16 11:35:51 +0530 (Wed, 16 Apr 2014)" );
	script_name( "Adobe Reader Denial of Service & Code Execution Vulnerabilities (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to denial of service and
code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws exist due to:

  - An array-indexing error when parsing protocol handler parameters.

  - An input validation error when parsing images.

  - Improper sanitization of certain unspecified user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code or
cause a denial of service." );
	script_tag( name: "affected", value: "Adobe Reader version 8.x before 8.2.5 and 9.x before 9.4 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader 8.2.5 or 9.4 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41435" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-21.html" );
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
if(vers && IsMatchRegexp( vers, "^[89]\\." )){
	if(version_in_range( version: vers, test_version: "8.0", test_version2: "8.2.4" ) || version_in_range( version: vers, test_version: "9.0", test_version2: "9.3.4" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

