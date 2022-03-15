if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800045" );
	script_version( "2021-08-11T13:58:23+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 13:58:23 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-10-30 06:53:04 +0100 (Thu, 30 Oct 2008)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2008-4696", "CVE-2008-4697", "CVE-2008-4698", "CVE-2008-4725" );
	script_bugtraq_id( 31842, 31869 );
	script_name( "Opera Web Browser Multiple XSS Vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://www.opera.com/support/search/view/903/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/search/view/904/" );
	script_xref( name: "URL", value: "http://www.opera.com/support/search/view/905/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_opera_detection_linux_900037.sc" );
	script_mandatory_keys( "Opera/Linux/Version" );
	script_tag( name: "impact", value: "Successful remote attack could inject arbitrary code, launch
  cross site attacks, information disclosure and can even steal related DB (DataBase) contents." );
	script_tag( name: "affected", value: "Opera version prior to 9.61 on Linux." );
	script_tag( name: "insight", value: "Flaws are due to:

  - the URL of visited pages are not properly sanitised by the History Search
    functionality before being used.

  - an error in the implementation of the Fast Forward feature.

  - an error while blocking scripts during a news feed preview." );
	script_tag( name: "solution", value: "Upgrade to Opera 9.61." );
	script_tag( name: "summary", value: "The host is installed with Opera Web Browser and is prone to
  multiple Cross Site Scripting (XSS) vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Linux/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "9.61" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "9.61" );
	security_message( port: 0, data: report );
}

