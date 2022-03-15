CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810963" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2017-9616", "CVE-2017-9617" );
	script_bugtraq_id( 99087, 99085 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-27 16:34:23 +0530 (Tue, 27 Jun 2017)" );
	script_name( "Wireshark Multiple Denial-of-Service Vulnerabilities-03 June17 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in 'epan/dissectors/file-mp4.c' script which fails to properly
    handle certain types of packets.

  - An error in the 'dissect_daap_one_tag' function in 'epan/dissectors/packet-daap.c'
    script in the DAAP dissector." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to crash the affected application, resulting in denial-of-service
  conditions." );
	script_tag( name: "solution", value: "Update to version 2.4.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13777" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13799" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: wirversion, test_version: "2.4.6" )){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "2.4.6" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

