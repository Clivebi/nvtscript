if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900350" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1597" );
	script_name( "Mozilla Firefox PDF JavaScript Restriction Bypass Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/503183/100/0/threaded" );
	script_xref( name: "URL", value: "http://secniche.org/papers/SNS_09_03_PDF_Silent_Form_Re_Purp_Attack.pdf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attacker execute arbitrary codes in the
  context of the malicious PDF file and execute arbitrary codes into the context
  of the remote system." );
	script_tag( name: "affected", value: "Firefox version 3.0.10 and prior on Windows." );
	script_tag( name: "insight", value: "Error while executing DOM calls in response to a javascript: URI in the target
  attribute of a submit element within a form contained in an inline PDF file
  which causes bypassing restricted Adobe's JavaScript restrictions." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.3 or later" );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone to
  PDF Javascript Restriction Bypass Vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.mozilla.com/en-US/index.html" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer == NULL){
	exit( 0 );
}
if(version_is_less_equal( version: ffVer, test_version: "3.0.10" )){
	report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "Less than or equal to 3.0.10" );
	security_message( port: 0, data: report );
}

