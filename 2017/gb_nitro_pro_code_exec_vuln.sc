CPE = "cpe:/a:nitro_software:nitro_pro";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811274" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2017-7442" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-04 13:57:00 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-08-08 14:54:42 +0530 (Tue, 08 Aug 2017)" );
	script_name( "Nitro Pro 'saveAs and launchURL' Code Execution Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Nitro Pro
  and is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unsafe javascript API
  implemented in Nitro Pro, the 'saveAs' function Javascript API function allows for
  writing arbitrary files to the file system. Additionally, the 'launchURL' function
  allows an attacker to execute local files on the file system and bypass the
  security dialog." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Nitro Pro version 11.0.3.173" );
	script_tag( name: "solution", value: "Upgrade to Nitro Pro version 11.0.5.271
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.rapid7.com/db/modules/exploit/windows/fileformat/nitro_reader_jsapi" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/42418" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_nitro_pro_detect_win.sc" );
	script_mandatory_keys( "Nitro/Pro/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!nitroVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_equal( version: nitroVer, test_version: "11.0.3.173" )){
	report = report_fixed_ver( installed_version: nitroVer, fixed_version: "Nitro Pro 11.0.5.271" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

