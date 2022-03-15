if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803070" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-6052", "CVE-2012-6054", "CVE-2012-6055", "CVE-2012-6056", "CVE-2012-6057" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-12-10 10:30:54 +0530 (Mon, 10 Dec 2012)" );
	script_name( "Wireshark Multiple Dissector Multiple Vulnerabilities - Dec12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51422" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-30.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-32.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-33.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-34.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2012-39.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain sensitive
  information, cause denial of service or to consume excessive CPU resources." );
	script_tag( name: "affected", value: "Wireshark versions 1.8.x before 1.8.4 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to

  - Hostname disclosure by reading pcap-ng files.

  - The dissect_sflow_245_address_type() in sFlow dissector fails to handle
    length calculations for an invalid IP address type.

  - Errors in 3GPP2 A11, SCTP and EIGRP dissectors, which can be exploited
    to cause a crash." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.8.4 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!sharkVer){
	exit( 0 );
}
if(version_in_range( version: sharkVer, test_version: "1.8.0", test_version2: "1.8.3" )){
	report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.8.0 - 1.8.3" );
	security_message( port: 0, data: report );
}

