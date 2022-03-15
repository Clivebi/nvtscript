if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902208" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-07-01 15:58:11 +0200 (Thu, 01 Jul 2010)" );
	script_cve_id( "CVE-2010-1203" );
	script_bugtraq_id( 41050 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Firefox Multiple Unspecified Vulnerabilities june-10 (Windows)" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=524921" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2010/mfsa2010-26.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code." );
	script_tag( name: "affected", value: "Firefox version 3.6.x before 3.6.4." );
	script_tag( name: "insight", value: "Multiple flaws are due to unspecified vulnerabilities in the 'JavaScript'
  engine, which allows  attackers to cause a denial of service or execute
  arbitrary code via unknown vectors." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.6.4." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to multiple unspecified
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "3.6.0", test_version2: "3.6.3" )){
		report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "3.6.0 - 3.6.3" );
		security_message( port: 0, data: report );
	}
}

