CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801516" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_cve_id( "CVE-2010-2883" );
	script_bugtraq_id( 43057 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)" );
	script_name( "Adobe Acrobat and Reader SING 'uniqueName' Buffer Overflow Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error within 'CoolType.dll' when processing the
'uniqueName' entry of SING tables in fonts." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to crash an affected application or
execute arbitrary code by tricking a user into opening a specially crafted PDF
document." );
	script_tag( name: "affected", value: "Adobe Reader version 9.3.4 and prior." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.4." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41340" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa10-02.html" );
	script_xref( name: "URL", value: "http://blog.metasploit.com/2010/09/return-of-unpublished-adobe.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: readerVer, test_version: "9.3.4" )){
	report = report_fixed_ver( installed_version: readerVer, fixed_version: "9.3.4" );
	security_message( port: 0, data: report );
}

