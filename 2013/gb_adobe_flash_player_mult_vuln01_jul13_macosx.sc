if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803832" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2013-3347", "CVE-2013-3345", "CVE-2013-3344" );
	script_bugtraq_id( 61048, 61045, 61043 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-07-25 17:41:58 +0530 (Thu, 25 Jul 2013)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities-01 July13 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 11.7.700.232 or 11.8.800.94 or later." );
	script_tag( name: "insight", value: "Multiple unspecified error exists and an integer overflow error exists
when resampling a PCM buffer." );
	script_tag( name: "affected", value: "Adobe Flash Player before 11.7.700.232 and 11.8.x before 11.8.800.94 on
Mac OS X" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
code on the target system will cause heap-based buffer overflow or cause
memory corruption via unspecified vectors." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53975" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-17.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
playerVer = get_kb_item( "Adobe/Flash/Player/MacOSX/Version" );
if(playerVer){
	if(version_is_less( version: playerVer, test_version: "11.7.700.232" ) || version_in_range( version: playerVer, test_version: "11.8.0", test_version2: "11.8.800.93" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

