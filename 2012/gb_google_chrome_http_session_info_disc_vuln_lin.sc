if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802701" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_cve_id( "CVE-2011-3022" );
	script_bugtraq_id( 52031 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2012-02-21 15:33:27 +0530 (Tue, 21 Feb 2012)" );
	script_name( "Google Chrome 'HTTP session' Information Disclosure Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48016/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/02/chrome-stable-update.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain sensitive information." );
	script_tag( name: "affected", value: "Google Chrome version prior to 17.0.963.56 and 19.x before 19.0.1036.7 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to 'translate/translate_manager.cc', which uses
  HTTP session to exchange data for translation, which allows remote attackers
  to obtain sensitive information by sniffing the network." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 17.0.963.56 or 19.0.1036.7 or later." );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to
  information disclosure vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "Google-Chrome/Linux/Ver" );
if(isnull( chromeVer )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "17.0.963.56" ) || version_in_range( version: chromeVer, test_version: "19.0", test_version2: "19.0.1036.6" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

