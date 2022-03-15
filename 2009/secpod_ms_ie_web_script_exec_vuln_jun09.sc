if(description){
	script_xref( name: "URL", value: "http://research.microsoft.com/apps/pubs/default.aspx?id=79323" );
	script_xref( name: "URL", value: "http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf" );
	script_oid( "1.3.6.1.4.1.25623.1.0.900366" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_cve_id( "CVE-2009-2057", "CVE-2009-2064", "CVE-2009-2069" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Microsoft Internet Explorer Web Script Execution Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  web script and spoof an arbitrary https site by letting a browser obtain a valid certificate." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version prior to 8.0." );
	script_tag( name: "insight", value: "- Error exists while the HTTP Host header to determine the context of a
  document provided in a '4xx' or '5xx' CONNECT response from a proxy server,
  and these can be exploited by modifying the CONNECT response, aka an 'SSL tampering' attack.

  - Displays a cached certificate for a '4xx' or '5xx' CONNECT response page
  returned by a proxy server, which can be exploited by sending the browser
  a crafted 502 response page upon a subsequent request." );
	script_tag( name: "solution", value: "Upgrade to latest version." );
	script_tag( name: "summary", value: "This host has Internet Explorer installed and is prone to Web
  Script Execution vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if( version_is_less( version: ieVer, test_version: "8.0" ) ){
	report = report_fixed_ver( installed_version: ieVer, fixed_version: "8.0" );
	security_message( port: 0, data: report );
}
else {
	if(version_in_range( version: ieVer, test_version: "8.0", test_version2: "8.0.6001.18782" )){
		report = report_fixed_ver( installed_version: ieVer, vulnerable_range: "8.0 - 8.0.6001.18782" );
		security_message( port: 0, data: report );
	}
}

