if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810227" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5096", "CVE-2013-7456", "CVE-2016-4649", "CVE-2016-4647", "CVE-2016-4648", "CVE-2016-4646", "CVE-2014-9862", "CVE-2016-4645", "CVE-2016-4644", "CVE-2016-4643", "CVE-2016-4642", "CVE-2016-4652", "CVE-2016-4637", "CVE-2016-4635", "CVE-2016-4634", "CVE-2016-4629", "CVE-2016-4630", "CVE-2016-4632", "CVE-2016-4631", "CVE-2016-4633", "CVE-2016-4626", "CVE-2016-4625", "CVE-2016-1863", "CVE-2016-4653", "CVE-2016-4582", "CVE-2016-1865", "CVE-2016-4621", "CVE-2016-0718", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4483", "CVE-2016-4614", "CVE-2016-4615", "CVE-2016-4616", "CVE-2016-4619", "CVE-2016-4449", "CVE-2016-1684", "CVE-2016-4607", "CVE-2016-4608", "CVE-2016-4609", "CVE-2016-4610", "CVE-2016-4612", "CVE-2016-4638", "CVE-2016-4640", "CVE-2016-4641", "CVE-2016-4639", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2176", "CVE-2016-1836", "CVE-2016-4594", "CVE-2016-4601", "CVE-2016-4599", "CVE-2016-4596", "CVE-2016-4597", "CVE-2016-4600", "CVE-2016-4602", "CVE-2016-4598", "CVE-2016-4595" );
	script_bugtraq_id( 90861, 90859, 91834 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)" );
	script_tag( name: "creation_date", value: "2016-12-02 12:37:39 +0530 (Fri, 02 Dec 2016)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities December-2016" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, escalate privileges,
  bypass certain protection mechanism and have other impacts." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.11.x before
  10.11.6" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X version
  10.11.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT206903" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.11" );
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
if(ContainsString( osName, "Mac OS X" ) && IsMatchRegexp( osVer, "^10\\.11" )){
	if(version_is_less( version: osVer, test_version: "10.11.6" )){
		report = report_fixed_ver( installed_version: osVer, fixed_version: "10.11.6" );
		security_message( data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

