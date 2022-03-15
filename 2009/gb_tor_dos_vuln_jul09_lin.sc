if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800841" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2425" );
	script_bugtraq_id( 35505 );
	script_name( "Tor Denial Of Service Vulnerability - July09 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35546" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51376" );
	script_xref( name: "URL", value: "http://archives.seul.org/or/announce/Jun-2009/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_tor_detect_lin.sc" );
	script_mandatory_keys( "Tor/Linux/Ver" );
	script_tag( name: "affected", value: "Tor version 0.2.x before 0.2.0.35 on Linux." );
	script_tag( name: "insight", value: "Error exists while parsing certain malformed router descriptors and can be
  exploited to crash Tor via specially crafted router descriptors." );
	script_tag( name: "solution", value: "Upgrade to version 0.2.0.35 or later" );
	script_tag( name: "summary", value: "This host is installed with Tor and is prone to Denial Of Service
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause Denial of Service." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
torVer = get_kb_item( "Tor/Linux/Ver" );
if(!torVer){
	exit( 0 );
}
torVer = ereg_replace( pattern: "-", replace: ".", string: torVer );
if(version_in_range( version: torVer, test_version: "0.2", test_version2: "0.2.0.34.alpha" )){
	report = report_fixed_ver( installed_version: torVer, vulnerable_range: "0.2 - 0.2.0.34.alpha" );
	security_message( port: 0, data: report );
	exit( 0 );
}

