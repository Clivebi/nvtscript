if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800046" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-10-30 06:53:04 +0100 (Thu, 30 Oct 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-4694", "CVE-2008-4695" );
	script_name( "Opera Remote Code Execution and Information Disclosure Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://www.opera.com/support/search/view/901/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/search/view/902/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful remote attack could inject arbitrary code, launch
  cross site attacks, information disclosure and can even steal related DB (DataBase) contents." );
	script_tag( name: "affected", value: "Opera version prior to 9.60 on Windows." );
	script_tag( name: "insight", value: "Flaws are due to:

  - an error in Opera.dll, that fails to anchor identifier (optional argument)

  - an unknown error in predicting the cache pathname of a cached Java
    applet and then launching this applet from the cache." );
	script_tag( name: "solution", value: "Upgrade to Opera 9.60 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera Web Browser and is prone to
  remote code execution and information disclosure Vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "9.60" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "9.60" );
	security_message( port: 0, data: report );
}

