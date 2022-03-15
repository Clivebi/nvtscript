CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811073" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_cve_id( "CVE-2017-9348", "CVE-2017-9347", "CVE-2017-9353" );
	script_bugtraq_id( 98801, 98800, 98805 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-20 12:29:00 +0000 (Wed, 20 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-06-02 16:53:21 +0530 (Fri, 02 Jun 2017)" );
	script_name( "Wireshark Multiple Denial-of-Service Vulnerabilities-02 June17 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the epan/dissectors/packet-ipv6.c script within the IPv6
    dissector which could crash.

  - An error in the epan/dissectors/asn1/ros/packet-ros-template.c script within
    the ROS dissector which could crash with a NULL pointer dereference.

  - An error in the epan/dissectors/packet-dof.c script within the DOF dissector
    which could read past the end of a buffer." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to crash wireshark and result in denial-of-service condition." );
	script_tag( name: "affected", value: "Wireshark version 2.2.0 through 2.2.6
  on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.2.7 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-23.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-31.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-33.html" );
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
if(IsMatchRegexp( wirversion, "^(2\\.2)" ) && version_is_less( version: wirversion, test_version: "2.2.7" )){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "2.2.7" );
	security_message( data: report );
	exit( 0 );
}

