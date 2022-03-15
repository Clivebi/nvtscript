CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811310" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2017-9766" );
	script_bugtraq_id( 99187 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-05 18:10:56 +0530 (Wed, 05 Jul 2017)" );
	script_name( "Wireshark 'profinet/packet-dcerpc-pn-io.c' DoS Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper handling
  of certain types of packets." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to crash the affected application, resulting in denial-of-service
  conditions." );
	script_tag( name: "affected", value: "Wireshark version 2.2.7 on MacOSX" );
	script_tag( name: "solution", value: "Apply the appropriate patch from vendor." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13811" );
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
if(wirversion == "2.2.7"){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "Apply the patch" );
	security_message( data: report );
	exit( 0 );
}

