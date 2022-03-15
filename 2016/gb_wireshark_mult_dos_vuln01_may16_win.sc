CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807575" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-4084", "CVE-2016-4083", "CVE-2016-4077", "CVE-2016-4076" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-05-03 11:09:01 +0530 (Tue, 03 May 2016)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities May16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - 'epan/dissectors/packet-ncp2222.inc' script in the NCP dissector does not
    properly initialize memory for search patterns.

  - 'epan/reassemble.c' script in TShark relies on incorrect special-case
    handling of truncated Tvb data structures.

  - 'epan/dissectors/packet-mswsp.c' script in the MS-WSP dissector does not
    ensure that data is available before array allocation.

  - An integer signedness error in 'epan/dissectors/packet-mswsp.c' script in
    the MS-WSP dissector" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 2.0.x before 2.0.3
  on Windows" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.0.3 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2016-27.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2016-20.html" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2016-19.html" );
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
if(version_in_range( version: wirversion, test_version: "2.0.0", test_version2: "2.0.2" )){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "2.0.3" );
	security_message( data: report );
	exit( 0 );
}

