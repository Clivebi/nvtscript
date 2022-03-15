CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807472" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_cve_id( "CVE-2016-1007", "CVE-2016-1008", "CVE-2016-1009" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-03 03:19:00 +0000 (Sat, 03 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-03-10 12:29:42 +0530 (Thu, 10 Mar 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Reader Multiple Vulnerabilities March16 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Some memory leak vulnerabilities.

  - An untrusted search path vulnerability in Adobe Download Manager" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Reader 11.x before 11.0.15 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 11.0.15
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb16-09.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Reader/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: readerVer, test_version: "11.0", test_version2: "11.0.14" )){
	report = report_fixed_ver( installed_version: readerVer, fixed_version: "11.0.15" );
	security_message( data: report );
	exit( 0 );
}

