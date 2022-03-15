if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801433" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)" );
	script_cve_id( "CVE-2010-2992" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Wireshark 'packet-gsm_a_rr.c' Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2010-08.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/Jul/1024269.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.2.10.html" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Wireshark version 1.2.2 through 1.2.9" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'packet-gsm_a_rr.c' in the GSM A RR
  dissector." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.2.10 or later." );
	script_tag( name: "summary", value: "The host is installed with Wireshark and is prone to Denial of
  Service Vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "1.2.2", test_version2: "1.2.9" )){
	report = report_fixed_ver( installed_version: wiresharkVer, vulnerable_range: "1.2.2 - 1.2.9" );
	security_message( port: 0, data: report );
}

