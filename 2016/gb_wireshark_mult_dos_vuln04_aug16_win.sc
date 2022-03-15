CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809102" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-5357", "CVE-2016-5356", "CVE-2016-5355", "CVE-2016-5354", "CVE-2016-5353", "CVE-2016-5351", "CVE-2016-5350" );
	script_bugtraq_id( 91140 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-08-12 09:53:38 +0530 (Fri, 12 Aug 2016)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities-04 August16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The 'epan/dissectors/packet-dcerpc-spoolss.c' script omits in the SPOOLS
    component mishandles unexpected offsets.

  - The 'epan/crypt/airpdcap.c' in the IEEE 802.11 dissector mishandles the
    lack of an EAPOL_RSN_KEY.

  - The 'epan/dissectors/packet-umts_fp.c' in the UMTS FP dissector mishandles
    the reserved C/T value.

  - The 'USB subsystem' mishandles class types.

  - The 'wiretap/toshiba.c' in the Toshiba file parser mishandles sscanf
    unsigned-integer processing.

  - The 'wiretap/cosine.c' in the CoSine file parser mishandles sscanf
    unsigned-integer processing.

  - The 'wiretap/netscreen.c' in the NetScreen file parser mishandles sscanf
    unsigned-integer processing." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 2.0.x before 2.0.4
  and 1.12.x before 1.12.12 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.0.4 or
  1.12.12 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/06/09/3" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-36.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-32.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-30.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-29.html" );
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
if( version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.11" ) ){
	fix = "1.12.12";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wirversion, test_version: "2.0", test_version2: "2.0.3" )){
		fix = "2.0.4";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

