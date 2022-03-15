CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902162" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_cve_id( "CVE-2010-0190", "CVE-2010-0191", "CVE-2010-0192", "CVE-2010-0193", "CVE-2010-0194", "CVE-2010-0195", "CVE-2010-0196", "CVE-2010-0197", "CVE-2010-0198", "CVE-2010-0199", "CVE-2010-0201", "CVE-2010-0202", "CVE-2010-0203", "CVE-2010-0204", "CVE-2010-1241" );
	script_bugtraq_id( 39329 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)" );
	script_name( "Adobe Acrobat and Reader PDF Handling Multiple Vulnerabilities (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to buffer overflows, memory corruptions and input validation
  errors when processing malformed data within a PDF document." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to inject malicious scripting code,
  disclose sensitive information or execute arbitrary code by tricking a user
  into opening a specially crafted PDF document." );
	script_tag( name: "affected", value: "Adobe Reader version 9.x before 9.3.2 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader/Acrobat version 9.3.2 or 8.2.2 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0873" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA10-103C.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-09.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( readerVer, "^9\\." )){
	if(version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.3.1" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "9.0 - 9.3.1" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

