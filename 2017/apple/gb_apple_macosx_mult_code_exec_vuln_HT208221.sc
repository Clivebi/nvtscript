if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811960" );
	script_version( "2021-09-09T14:37:40+0000" );
	script_cve_id( "CVE-2017-13832", "CVE-2016-2161", "CVE-2016-5387", "CVE-2016-8740", "CVE-2016-8743", "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7659", "CVE-2017-7668", "CVE-2017-7679", "CVE-2017-9788", "CVE-2017-9789", "CVE-2017-13825", "CVE-2017-13809", "CVE-2017-13820", "CVE-2017-13821", "CVE-2017-13815", "CVE-2017-13828", "CVE-2017-13811", "CVE-2017-13830", "CVE-2017-11103", "CVE-2017-13819", "CVE-2017-13814", "CVE-2017-13831", "CVE-2017-13810", "CVE-2017-13817", "CVE-2017-13818", "CVE-2017-13836", "CVE-2017-13841", "CVE-2017-13840", "CVE-2017-13842", "CVE-2017-13782", "CVE-2017-13843", "CVE-2017-13813", "CVE-2017-13816", "CVE-2017-13812", "CVE-2016-4736", "CVE-2017-13824", "CVE-2017-13846", "CVE-2017-13826", "CVE-2017-13822", "CVE-2017-7132", "CVE-2017-13823", "CVE-2017-13808", "CVE-2017-13838" );
	script_bugtraq_id( 95076, 91816, 94650, 95077, 99135, 99134, 99132, 99137, 99170, 99569, 99568, 99551, 93055, 101637 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 14:37:40 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-27 17:46:00 +0000 (Mon, 27 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-07-20 12:23:38 +0530 (Thu, 20 Jul 2017)" );
	script_name( "Apple MacOSX Multiple Code Execution Vulnerabilities HT208221" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple memory corruption
  issues in libxpc component." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code with system privileges." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.12.x through
  10.12.6 and 10.11.x through 10.11.6." );
	script_tag( name: "solution", value: "Apply appropriate security patch from the vendor.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208221" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.1[12]" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[12]" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(IsMatchRegexp( osVer, "^10\\.1[12]" )){
	if( version_in_range( version: osVer, test_version: "10.11", test_version2: "10.11.5" ) || version_in_range( version: osVer, test_version: "10.12", test_version2: "10.12.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.11.6" || osVer == "10.12.6"){
			buildVer = get_kb_item( "ssh/login/osx_build" );
			if(osVer == "10.11.6" && version_is_less( version: buildVer, test_version: "15G17023" ) || osVer == "10.12.6" && version_is_less( version: buildVer, test_version: "16G1036" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

