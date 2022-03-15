CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106721" );
	script_cve_id( "CVE-2016-9197" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_name( "Cisco Mobility Express 2800 and 3800 Series Wireless LAN Controllers Shell Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cme" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See vendor advisory." );
	script_tag( name: "summary", value: "A vulnerability in the CLI command parser of the Cisco Mobility Express 2800
and 3800 Series Wireless LAN Controllers could allow an authenticated, local attacker to obtain access to the
underlying operating system shell with root-level privileges." );
	script_tag( name: "insight", value: "The vulnerability is due to incorrect permissions being assigned to
configured users on the device. An attacker could exploit this vulnerability by authenticating to the device and
issuing certain commands at the CLI." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to access the underlying
operating system shell with root access." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-13 15:04:00 +0000 (Thu, 13 Apr 2017)" );
	script_tag( name: "creation_date", value: "2017-04-07 10:27:08 +0200 (Fri, 07 Apr 2017)" );
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
if(!model || !IsMatchRegexp( model, "^AIR-AP(2|3)8[0-9]{2}" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version == "8.3.102.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

