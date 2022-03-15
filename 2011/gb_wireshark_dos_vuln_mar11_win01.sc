if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801756" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)" );
	script_cve_id( "CVE-2011-1138" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Wireshark Denial of Service Vulnerability - March-11 (Windows)" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2011-04.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5722" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.4.4.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a denial of
  service." );
	script_tag( name: "affected", value: "Wireshark version 1.4.0 through 1.4.3" );
	script_tag( name: "insight", value: "The flaw is due to 'Off-by-one' error in the dissect_6lowpan_iphc
  function in packet-6lowpan.c" );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.4.4" );
	script_tag( name: "summary", value: "The host is installed with Wireshark and is prone to multiple DoS
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "1.4.0", test_version2: "1.4.3" )){
	report = report_fixed_ver( installed_version: wiresharkVer, vulnerable_range: "1.4.0 - 1.4.3" );
	security_message( port: 0, data: report );
}

