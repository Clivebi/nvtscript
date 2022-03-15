CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801366" );
	script_version( "$Revision: 12653 $" );
	script_cve_id( "CVE-2010-1285", "CVE-2010-1295", "CVE-2010-2168", "CVE-2010-2201", "CVE-2010-2202", "CVE-2010-2203", "CVE-2010-2204", "CVE-2010-2205", "CVE-2010-2206", "CVE-2010-2207", "CVE-2010-2208", "CVE-2010-2209", "CVE-2010-2210", "CVE-2010-2211", "CVE-2010-2212" );
	script_bugtraq_id( 41230, 41232, 41236, 41234, 41235, 41231, 41231, 41241, 41239, 41244, 41240, 41242, 41243, 41245 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)" );
	script_name( "Adobe Reader Multiple Vulnerabilities -July10 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are caused by memory corruptions, invalid pointers reference,
uninitialized memory, array-indexing and use-after-free errors when processing
malformed data within a PDF document." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to crash an affected application or
execute arbitrary code by tricking a user into opening a specially crafted PDF
document." );
	script_tag( name: "affected", value: "Adobe Reader version 8.x before 8.2.3 and 9.x before 9.3.3 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.3.3 or 8.2.3 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://isc.incidents.org/diary.html?storyid=9100" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1636" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-15.html" );
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
if(IsMatchRegexp( readerVer, "^(8|9)" )){
	if(version_in_range( version: readerVer, test_version: "8.0", test_version2: "8.2.2" ) || version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.3.2" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

