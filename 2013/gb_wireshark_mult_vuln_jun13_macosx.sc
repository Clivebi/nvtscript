if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803655" );
	script_version( "2019-09-16T06:54:58+0000" );
	script_cve_id( "CVE-2013-4082", "CVE-2013-4080", "CVE-2013-4079", "CVE-2013-4078", "CVE-2013-4077", "CVE-2013-4076", "CVE-2013-4075" );
	script_bugtraq_id( 60506, 60503, 60498, 60495, 60502, 60499, 60501 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-09-16 06:54:58 +0000 (Mon, 16 Sep 2019)" );
	script_tag( name: "creation_date", value: "2013-05-28 13:52:52 +0530 (Tue, 28 May 2013)" );
	script_name( "Wireshark Multiple Vulnerabilities - June 13 (Mac OS X)" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028648" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause application
  crash, consume memory or heap-based buffer overflow." );
	script_tag( name: "affected", value: "Wireshark 1.8.x before 1.8.8 on Mac OS X." );
	script_tag( name: "insight", value: "Multiple flaws due to errors in,

  - 'epan/dissectors/packet-gmr1_bcch.c' in GMR-1 BCCH dissector

  - dissect_iphc_crtp_fh() function in 'epan/dissectors/packet-ppp.c' in PPP
  dissector

  - Array index error in NBAP dissector

  - 'epan/dissectors/packet-rdp.c' in the RDP dissector

  - dissect_schedule_message() function in 'epan/dissectors/packet-gsm_cbch.c'
  in GSM CBCH dissector

  - dissect_r3_upstreamcommand_queryconfig() function in
  'epan/dissectors/packet-assa_r3.c' in Assa Abloy R3 dissector

  - vwr_read() function in 'wiretap/vwr.c' in Ixia IxVeriWave file parser." );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.8.8 or later." );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(sharkVer && IsMatchRegexp( sharkVer, "^1\\.8" )){
	if(version_in_range( version: sharkVer, test_version: "1.8.0", test_version2: "1.8.7" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

