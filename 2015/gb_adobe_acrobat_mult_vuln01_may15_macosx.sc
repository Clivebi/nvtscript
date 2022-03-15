CPE = "cpe:/a:adobe:acrobat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805386" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-3076", "CVE-2015-3075", "CVE-2015-3074", "CVE-2015-3073", "CVE-2015-3072", "CVE-2015-3071", "CVE-2015-3070", "CVE-2015-3069", "CVE-2015-3068", "CVE-2015-3067", "CVE-2015-3066", "CVE-2015-3065", "CVE-2015-3064", "CVE-2015-3063", "CVE-2015-3062", "CVE-2015-3061", "CVE-2015-3060", "CVE-2015-3059", "CVE-2015-3058", "CVE-2015-3057", "CVE-2015-3056", "CVE-2015-3055", "CVE-2015-3054", "CVE-2015-3053", "CVE-2015-3052", "CVE-2015-3051", "CVE-2015-3050", "CVE-2015-3049", "CVE-2015-3048", "CVE-2015-3046", "CVE-2015-3047", "CVE-2014-9160" );
	script_bugtraq_id( 74600, 74602, 74604, 74604, 74604, 74604, 74600, 74604, 74604, 74604, 74604, 74604, 74604, 74604, 74604, 74604, 74604, 74602, 74618, 74600, 74600, 74602, 74602, 74602, 74600, 74600, 74600, 74600, 74603, 74600, 74601, 74599 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-05-15 13:23:06 +0530 (Fri, 15 May 2015)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Acrobat Multiple Vulnerabilities - 01 May15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Error 'ScriptBridgeUtils', 'AFParseDate', 'ADBCAnnotEnumerator'
    'WDAnnotEnumerator', 'AFNSimple_Calculate', and 'app.Monitors'.

  - Multiple user-supplied inputs are not properly validated, and an
    use-after-free error." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to conduct a denial of service, bypass certain security restrictions,
  execute arbitrary code and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Acrobat 10.x before 10.1.14 and
  11.x before 11.0.11 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat version 10.1.14 or
  11.0.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/reader/apsb15-10.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Acrobat/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!acrobatVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: acrobatVer, test_version: "10.0", test_version2: "10.1.13" )){
	fix = "10.1.14";
	VULN = TRUE;
}
if(version_in_range( version: acrobatVer, test_version: "11.0", test_version2: "11.0.10" )){
	fix = "11.0.11";
	VULN = TRUE;
}
if(VULN){
	report = "Installed version: " + acrobatVer + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

