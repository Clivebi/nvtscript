CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106731" );
	script_cve_id( "CVE-2016-9196" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_name( "Cisco Aironet 1800, 2800, and 3800 Series Access Point Platforms Shell Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-aironet" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in login authentication management in Cisco Aironet 1800,
2800, and 3800 Series Access Point platforms could allow an authenticated, local attacker to gain unrestricted
root access to the underlying Linux operating system. The root Linux shell is provided for advanced troubleshooting
and should not be available to individual users, even those with root privileges. The attacker must have the root
password to exploit this vulnerability." );
	script_tag( name: "insight", value: "The vulnerability occurs because of incorrect management of user credentials
when the user authenticates to the device. An attacker could exploit this vulnerability by authenticating to the
affected device with the root account." );
	script_tag( name: "impact", value: "An exploit could allow the authenticated, privileged attacker to bypass the
controls required for root Linux shell access. If the authenticated user obtains root Linux shell access, further
compromise may be possible." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-04-07 13:36:40 +0200 (Fri, 07 Apr 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wlc_consolidation.sc" );
	script_mandatory_keys( "cisco/wlc/detected", "cisco/wlc/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
model = get_kb_item( "cisco/wlc/model" );
if(!model || !IsMatchRegexp( model, "^AIR-AP18(3|5)[0-9]{2}" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "8.1.112.3",
	 "8.1.112.4",
	 "8.1.15.14",
	 "8.1.131.0",
	 "8.2.100.0",
	 "8.2.102.43" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

