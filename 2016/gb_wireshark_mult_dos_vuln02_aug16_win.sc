CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808287" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-6511", "CVE-2016-6509", "CVE-2016-6510", "CVE-2016-6508", "CVE-2016-6506", "CVE-2016-6505" );
	script_bugtraq_id( 92169, 92168, 92173, 92166, 92165, 92163 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-08-09 10:31:32 +0530 (Tue, 09 Aug 2016)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities-02 August16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in 'epan/proto.c' script cause OpenFlow dissector
    (and possibly others) to go into a long loop.

  - The 'epan/dissectors/packet-ldss.c' script in the LDSS dissector mishandles
    conversations.

  - An Off-by-one error in 'epan/dissectors/packet-rlc.c' script in the
    RLC dissector.

  - The 'epan/dissectors/packet-rlc.c' in the RLC dissector uses an
    incorrect integer data type.

  - An error in 'epan/dissectors/packet-wsp.c' script cause WSP dissector
    to go into a long loop.

  - An error in 'epan/dissectors/packet-packetbb.c' script could cause a
    divide-by-zero error in PacketBB dissector." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.13 and
  2.0.x before 2.0.5 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.12.13 or
  2.0.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2016/07/28/3" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-47.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-45.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-46.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-44.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.12" ) ){
	fix = "1.12.13";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wirversion, test_version: "2.0", test_version2: "2.0.4" )){
		fix = "2.0.5";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

