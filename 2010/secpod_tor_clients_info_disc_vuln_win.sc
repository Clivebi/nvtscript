if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902102" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-0384" );
	script_name( "Tor Clients Information Disclosure Vulnerability (win)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38198" );
	script_xref( name: "URL", value: "http://archives.seul.org/or/announce/Jan-2010/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_tor_detect_win.sc" );
	script_mandatory_keys( "Tor/Win/Ver" );
	script_tag( name: "affected", value: "Tor version 0.2.2.x before 0.2.2.7-alpha on Windows." );
	script_tag( name: "insight", value: "This issue is due to directory mirror which does not prevent logging of the
  client IP address upon detection of erroneous client behavior, which might make
  it easier for local users to discover the identities of clients by reading log files." );
	script_tag( name: "solution", value: "Upgrade to version 0.2.2.7-alpha" );
	script_tag( name: "summary", value: "This host is installed with Tor and is prone to Information Disclosure
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to obtain client IP information
  that can help them launch further attacks." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("version_func.inc.sc");
torVer = get_kb_item( "Tor/Win/Ver" );
if(!torVer){
	exit( 0 );
}
torVer = ereg_replace( pattern: "-", replace: ".", string: torVer );
if(IsMatchRegexp( torVer, "^0\\.2\\.2\\." )){
	if(version_is_less( version: torVer, test_version: "0.2.2.7.alpha" )){
		report = report_fixed_ver( installed_version: torVer, fixed_version: "0.2.2.7.alpha" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

