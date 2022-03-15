CPE = "cpe:/a:adobe:dng_converter";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809764" );
	script_version( "$Revision: 12431 $" );
	script_cve_id( "CVE-2016-7856" );
	script_bugtraq_id( 94875 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-15 17:29:13 +0530 (Thu, 15 Dec 2016)" );
	script_name( "Adobe DNG Converter Memory Corruption Vulnerability - (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe DNG
  Converter and is prone to memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to some unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  run arbitrary code execution or conduct a denial-of-service condition." );
	script_tag( name: "affected", value: "Adobe DNG Converter prior to version 9.8 on
  Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Adobe DNG Converter version 9.8
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/dng-converter/apsb16-41.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_dng_converter_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/DNG/Converter/MACOSX/Version" );
	script_xref( name: "URL", value: "https://www.adobe.com/support/downloads/product.jsp?platform=Macintosh&product=106" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!adVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: adVer, test_version: "9.8.692" )){
	report = report_fixed_ver( installed_version: adVer, fixed_version: "9.8" );
	security_message( data: report );
	exit( 0 );
}

