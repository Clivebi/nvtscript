if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802331" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)" );
	script_cve_id( "CVE-2011-2943", "CVE-2011-3184", "CVE-2011-3185" );
	script_bugtraq_id( 49268 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Pidgin Libpurple Protocol Plugins Denial of Service Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45663" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=53" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=54" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=55" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025961" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_pidgin_detect_win.sc" );
	script_mandatory_keys( "Pidgin/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code,
  obtain sensitive information or cause a denial of service." );
	script_tag( name: "affected", value: "Pidgin versions prior to 2.10.0" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the IRC protocol plugin in libpurple when handling WHO
    responses with special characters in the nicknames.

  - An error in the MSN protocol plugin when handling HTTP 100 responses.

  - Improper handling of 'file:// URI', allows to execute the file when user
    clicks on a file:// URI in a received IM." );
	script_tag( name: "solution", value: "Upgrade to Pidgin version 2.10.0 or later." );
	script_tag( name: "summary", value: "This host is installed with Pidgin and is prone to denial of
  service vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
pidginVer = get_kb_item( "Pidgin/Win/Ver" );
if(pidginVer != NULL){
	if(version_is_less( version: pidginVer, test_version: "2.10.0" )){
		report = report_fixed_ver( installed_version: pidginVer, fixed_version: "2.10.0" );
		security_message( port: 0, data: report );
	}
}

