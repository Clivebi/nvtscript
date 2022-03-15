CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808582" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2016-4191", "CVE-2016-4192", "CVE-2016-4193", "CVE-2016-4194", "CVE-2016-4195", "CVE-2016-4196", "CVE-2016-4197", "CVE-2016-4198", "CVE-2016-4199", "CVE-2016-4200", "CVE-2016-4201", "CVE-2016-4202", "CVE-2016-4203", "CVE-2016-4204", "CVE-2016-4205", "CVE-2016-4206", "CVE-2016-4207", "CVE-2016-4208", "CVE-2016-4209", "CVE-2016-4210", "CVE-2016-4211", "CVE-2016-4212", "CVE-2016-4213", "CVE-2016-4214", "CVE-2016-4215", "CVE-2016-4250", "CVE-2016-4251", "CVE-2016-4252", "CVE-2016-4254", "CVE-2016-4255", "CVE-2016-4265", "CVE-2016-4266", "CVE-2016-4267", "CVE-2016-4268", "CVE-2016-4269", "CVE-2016-4270", "CVE-2016-4119", "CVE-2016-6937", "CVE-2016-6938" );
	script_bugtraq_id( 91716, 91712, 91714, 93016, 93014 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)" );
	script_tag( name: "creation_date", value: "2016-07-14 13:02:40 +0530 (Thu, 14 Jul 2016)" );
	script_name( "Adobe Reader Security Updates(apsb16-26)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An integer overflow vulnerability.

  - An use-after-free vulnerability.

  - A heap buffer overflow vulnerability.

  - A Memory corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attacker lead to code execution and
  to bypass JavaScript API execution restrictions." );
	script_tag( name: "affected", value: "Adobe Reader version 11.x before 11.0.17 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version
  11.0.17 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb16-26.html" );
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
if(IsMatchRegexp( !readerVer, "^(11\\.)" )){
	exit( 0 );
}
if(version_in_range( version: readerVer, test_version: "11.0", test_version2: "11.0.16" )){
	report = report_fixed_ver( installed_version: readerVer, fixed_version: "11.0.17" );
	security_message( data: report );
	exit( 0 );
}

