if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810567" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2016-7411", "CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418", "CVE-2016-7609", "CVE-2016-7628", "CVE-2016-7658", "CVE-2016-7659", "CVE-2016-7624", "CVE-2016-7605", "CVE-2016-7617", "CVE-2016-7647", "CVE-2016-7663", "CVE-2016-7627", "CVE-2016-7655", "CVE-2016-7588", "CVE-2016-7603", "CVE-2016-7595", "CVE-2016-7667", "CVE-2016-5419", "CVE-2016-5420", "CVE-2016-5421", "CVE-2016-7141", "CVE-2016-7167", "CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624", "CVE-2016-8625", "CVE-2016-7633", "CVE-2016-7616", "CVE-2016-4691", "CVE-2016-7618", "CVE-2016-7622", "CVE-2016-7594", "CVE-2016-7643", "CVE-2016-7602", "CVE-2016-7608", "CVE-2016-7591", "CVE-2016-7657", "CVE-2016-7625", "CVE-2016-7714", "CVE-2016-7620", "CVE-2016-7606", "CVE-2016-7612", "CVE-2016-7607", "CVE-2016-7615", "CVE-2016-7621", "CVE-2016-7637", "CVE-2016-7644", "CVE-2016-7629", "CVE-2016-7619", "CVE-2016-1777", "CVE-2016-7600", "CVE-2016-7742", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-7661", "CVE-2016-4693", "CVE-2016-7636", "CVE-2016-7662", "CVE-2016-7660", "CVE-2016-7761" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-02-22 17:03:09 +0530 (Wed, 22 Feb 2017)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities-01 February-2017" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, bypass certain protection
  mechanism and have other impacts." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.12.x through
  10.12.1" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X version
  10.12.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207423" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.12" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer){
	exit( 0 );
}
if(ContainsString( osName, "Mac OS X" )){
	if(IsMatchRegexp( osVer, "^10\\.12" ) && version_is_less( version: osVer, test_version: "10.12.2" )){
		report = report_fixed_ver( installed_version: osVer, fixed_version: "10.12.2" );
		security_message( data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

