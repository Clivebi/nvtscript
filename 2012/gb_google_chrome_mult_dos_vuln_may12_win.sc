if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802848" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2011-3078", "CVE-2011-3079", "CVE-2011-3080", "CVE-2011-3081", "CVE-2012-1521" );
	script_bugtraq_id( 53309 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-05-07 15:15:45 +0530 (Mon, 07 May 2012)" );
	script_name( "Google Chrome Multiple Denial of Service Vulnerabilities - May 12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48992/" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027001" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/04/stable-channel-update_30.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 18.0.1025.168 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to

  - Multiple use after free errors exists, when handling floats.

  - A use after free error exists within the xml parser.

  - An error exists within the IPC validation.

  - A race condition exists within the sandbox IPC." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 18.0.1025.168 or later." );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
  denial of service vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "18.0.1025.168" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "18.0.1025.168" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

