CPE = "cpe:/a:adobe:indesign_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810243" );
	script_version( "2019-07-05T09:29:25+0000" );
	script_cve_id( "CVE-2016-7886" );
	script_bugtraq_id( 94868 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 09:29:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-12-15 12:59:49 +0530 (Thu, 15 Dec 2016)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_name( "Adobe InDesign Server Memory Corruption Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is running Adobe InDesign Server and is
  prone to a memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified memory
  corruption error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected applications." );
	script_tag( name: "affected", value: "Adobe InDesign Server 11.0.0 and earlier
  versions on macosx." );
	script_tag( name: "solution", value: "Upgrade to version 12.0.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/indesign/apsb16-43.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_indesign_server_detect_macosx.sc" );
	script_mandatory_keys( "InDesign/Server/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
desVer = get_app_version( cpe: CPE );
if(!desVer){
	exit( 0 );
}
if(version_is_less( version: desVer, test_version: "12.0.0" )){
	report = report_fixed_ver( installed_version: desVer, fixed_version: "12.0.0" );
	security_message( data: report );
	exit( 0 );
}

