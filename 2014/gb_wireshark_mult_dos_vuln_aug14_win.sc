CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804800" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164", "CVE-2014-5165" );
	script_bugtraq_id( 69001, 69003, 69005, 69002, 69000 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-08-07 10:00:42 +0530 (Thu, 07 Aug 2014)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities-01 Aug14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to multiple denial of
service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in 'dissect_log' function in plugins/irda/packet-irda.c within the
ASN.1 BER dissector.

  - An error in 'read_new_line' function in wiretap/catapult_dct2000.c within the
Catapult DCT2000 dissector.

  - An error in 'APN decode' functionality in epan/dissectors/packet-gtp.c and
epan/dissectors/packet-gsm_a_gm.c within the GTP and GSM Management dissectors.

  - An error in 'rlc_decode_li' function in epan/dissectors/packet-rlc.c within
the RLC dissector.

  - An error in 'dissect_ber_constrained_bitstring' function in
epan/dissectors/packet-ber.c within the ASN.1 BER dissector." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct a DoS (Denial of
Service)." );
	script_tag( name: "affected", value: "Wireshark version 1.10.x before 1.10.9 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.10.9 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59299" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2014-09.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2014-08.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2014-10.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2014-11.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!sharkVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( sharkVer, "^(1\\.10)" )){
	if(version_in_range( version: sharkVer, test_version: "1.10.0", test_version2: "1.10.8" )){
		report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.10.0 - 1.10.8" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

