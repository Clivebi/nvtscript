if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812305" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-30 02:29:00 +0000 (Sat, 30 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-11-29 15:25:36 +0530 (Wed, 29 Nov 2017)" );
	script_cve_id( "CVE-2017-13872" );
	script_name( "Apple MacOSX High Sierra Local Root Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X High
  Sierra and is prone to local root authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error which
  allows anyone to log into system as root with empty password." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attacker to gain administrative access to the system." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.13.x" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.13.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://thehackernews.com/2017/11/mac-os-password-hack.html" );
	script_xref( name: "URL", value: "https://techcrunch.com/2017/11/28/astonishing-os-x-bug-lets-anyone-log-into-a-high-sierra-machine" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208315" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.13" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.13" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if( osVer == "10.13" ){
	VULN = TRUE;
	install = osVer;
}
else {
	if(osVer == "10.13.1"){
		buildVer = get_kb_item( "ssh/login/osx_build" );
		if(buildVer){
			if(version_is_less( version: buildVer, test_version: "17B48" )){
				VULN = TRUE;
				install = osVer + " build " + buildVer;
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: install, fixed_version: "10.13.2" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

