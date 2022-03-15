CPE = "cpe:/a:adobe:acrobat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813232" );
	script_version( "2021-06-02T11:05:57+0000" );
	script_cve_id( "CVE-2018-4990", "CVE-2018-4947", "CVE-2018-4948", "CVE-2018-4966", "CVE-2018-4968", "CVE-2018-4978", "CVE-2018-4982", "CVE-2018-4984", "CVE-2018-4996", "CVE-2018-4952", "CVE-2018-4954", "CVE-2018-4958", "CVE-2018-4959", "CVE-2018-4961", "CVE-2018-4971", "CVE-2018-4974", "CVE-2018-4977", "CVE-2018-4980", "CVE-2018-4983", "CVE-2018-4988", "CVE-2018-4989", "CVE-2018-4950", "CVE-2018-4979", "CVE-2018-4949", "CVE-2018-4951", "CVE-2018-4955", "CVE-2018-4956", "CVE-2018-4957", "CVE-2018-4962", "CVE-2018-4963", "CVE-2018-4964", "CVE-2018-4967", "CVE-2018-4969", "CVE-2018-4970", "CVE-2018-4972", "CVE-2018-4973", "CVE-2018-4975", "CVE-2018-4976", "CVE-2018-4981", "CVE-2018-4986", "CVE-2018-4985", "CVE-2018-4953", "CVE-2018-4987", "CVE-2018-4965", "CVE-2018-4993", "CVE-2018-4995", "CVE-2018-4960", "CVE-2018-12812", "CVE-2018-12815" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-02 11:05:57 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-15 12:13:36 +0530 (Tue, 15 May 2018)" );
	script_name( "Adobe Acrobat 2017 Security Updates(apsb18-09)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat 2017
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to double
  Free, heap overflow, use-after-free, out-of-bounds write, security bypass,
  out-of-bounds read, type confusion, untrusted pointer dereference, memory
  corruption, NTLM SSO hash theft and HTTP POST new line injection via XFA
  submission errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to bypass security, disclose information and run arbitrary code in the
  context of the current user." );
	script_tag( name: "affected", value: "Adobe Acrobat 2017 before 2017.011.30080 on
  MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat 2017 version
  2017.011.30080 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb18-09.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Acrobat/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "17.0", test_version2: "17.011.30079" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "17.011.30080 (2017.011.30080)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

