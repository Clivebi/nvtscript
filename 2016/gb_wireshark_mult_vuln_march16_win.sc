CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807448" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-2532", "CVE-2016-2531", "CVE-2016-2523", "CVE-2016-2521", "CVE-2016-4421", "CVE-2016-4418", "CVE-2016-4417" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-03 10:39:01 +0530 (Thu, 03 Mar 2016)" );
	script_name( "Wireshark Multiple Vulnerabilities March16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The 'dissect_llrp_parameters' function in 'epan/dissectors/packet-llrp.c' script
    in the LLRP dissector does not limit the recursion depth.

  - The Off-by-one error in 'epan/dissectors/packet-rsl.c' script in the RSL
    dissector.

  - The 'dnp3_al_process_object' function in 'epan/dissectors/packet-dnp.c' script
    in the DNP3 dissector

  - An untrusted search path vulnerability in the Application class
    'ui/qt/wireshark_application.cpp' script.

  - Multiple errors in 'epan/dissectors/packet-ber.c' script in the ASN.1 BER dissector.

  - An Off-by-one error in 'epan/dissectors/packet-gsm_abis_oml.c' script in the
    GSM A-bis OML dissector." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack and local users to gain privileges." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.10
  and 2.0.x before 2.0.2 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.12.10 or
  2.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2016-01.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2016-03.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2016-10.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2016-11.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-18.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
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
if( version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.9" ) ){
	fix = "1.12.10";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wirversion, test_version: "2.0.0", test_version2: "2.0.1" )){
		fix = "2.0.2";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

