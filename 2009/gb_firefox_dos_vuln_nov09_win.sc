if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801134" );
	script_version( "2021-09-14T09:46:07+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 09:46:07 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3382" );
	script_bugtraq_id( 36866 );
	script_name( "Mozilla Firefox DoS Vulnerability (Nov 2009) - Windows" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=514960" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-64.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Denial of Service or arbitrary code execution." );
	script_tag( name: "affected", value: "Firefox version 3.0 before 3.0.15." );
	script_tag( name: "insight", value: "A memory corruption error in
  layout/base/nsCSSFrameConstructor.cpp in the browser engine can be exploited to potentially
  execute arbitrary code or crash the browser." );
	script_tag( name: "solution", value: "Update to version 3.0.15 or later." );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to a denial of service (DoS)
  vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(!vers){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.0", test_version2: "3.0.14" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "3.0 - 3.0.14" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

