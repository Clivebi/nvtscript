CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800701" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_cve_id( "CVE-2009-1493", "CVE-2009-1492" );
	script_bugtraq_id( 34740, 34736 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_name( "Adobe Reader Denial of Service Vulnerability (May09)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to Denial of Service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "These flaws are due to a memory corruption errors in 'customDictionaryOpen'
  and 'getAnnots' methods in the JavaScript API while processing malicious PDF
  files with a long string in the second argument." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause memory corruption or
  denial of service." );
	script_tag( name: "affected", value: "Adobe Reader version 9.1 and prior on Linux." );
	script_tag( name: "solution", value: "Upgrade Adobe Reader version 9.3.2 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34924" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50146" );
	script_xref( name: "URL", value: "http://packetstorm.linuxsecurity.com/0904-exploits/spell.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
readerVer = ereg_replace( pattern: "\\_", replace: ".", string: readerVer );
if(readerVer == NULL){
	exit( 0 );
}
if(version_is_less_equal( version: readerVer, test_version: "9.1" )){
	report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "Less than or equal to 9.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}

