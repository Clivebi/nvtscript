CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106709" );
	script_cve_id( "CVE-2017-3834" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_name( "Cisco Aironet 1830 Series and 1850 Series Access Points Mobility Express Default Credential Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-ame" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in Cisco Aironet 1830 Series and Cisco Aironet 1850 Series
Access Points running Cisco Mobility Express Software could allow an unauthenticated, remote attacker to take
complete control of an affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to the existence of default credentials for an
affected device that is running Cisco Mobility Express Software, regardless of whether the device is configured
as a master, subordinate, or standalone access point. An attacker who has layer 3 connectivity to an affected
device could use Secure Shell (SSH) to log in to the device with elevated privileges." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to take complete control of the
device." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-22 19:31:00 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-04-07 08:38:56 +0200 (Fri, 07 Apr 2017)" );
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
affected = make_list( "8.2.100.0",
	 "8.2.102.43",
	 "8.2.130.0",
	 "8.2.121.12",
	 "8.2.102.139",
	 "8.2.121.12",
	 "8.3.102.0",
	 "8.2.121.12" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

