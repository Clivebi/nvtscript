if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810570" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_cve_id( "CVE-2016-4662", "CVE-2016-4682", "CVE-2016-4669", "CVE-2016-4675", "CVE-2016-4663" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-02-28 09:04:00 +0530 (Tue, 28 Feb 2017)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities-04 February-2017" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A memory corruption issue in 'NVIDIA Graphics Drivers'.

  - A logic issue in 'libxpc'.

  - Multiple input validation issues in 'MIG generated code'.

  - An out-of-bounds read issue in the 'SGI image parsing'.

  - A memory corruption issue in 'AppleGraphicsControl'." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service and gain access to
  potentially sensitive information." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.11.x through
  10.11.6 and 10.10.x through 10.10.5" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207275" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.1[01]" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[01]" )){
	exit( 0 );
}
if( version_in_range( version: osVer, test_version: "10.10", test_version2: "10.10.4" ) || version_in_range( version: osVer, test_version: "10.11", test_version2: "10.11.5" ) ){
	fix = "Upgrade to latest OS release and apply patch from vendor";
}
else {
	if(osVer == "10.11.6" || osVer == "10.10.5"){
		buildVer = get_kb_item( "ssh/login/osx_build" );
		if(buildVer){
			if(( osVer == "10.11.6" && version_is_less( version: buildVer, test_version: "15G1108" ) ) || ( osVer == "10.10.5" && version_is_less( version: buildVer, test_version: "14F1713" ) )){
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

