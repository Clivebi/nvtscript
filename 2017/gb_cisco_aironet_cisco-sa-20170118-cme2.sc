CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106626" );
	script_cve_id( "CVE-2016-9221" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_name( "Cisco Mobility Express 2800 and 3800 802.11 Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-cme2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in 802.11 ingress connection authentication handling for the
Cisco Mobility Express 2800 and 3800 Access Points could allow an unauthenticated, adjacent attacker to cause
authentication to fail." );
	script_tag( name: "insight", value: "The vulnerability is due to improper error handling for 802.11 authentication
requests that do not complete. An attacker could exploit this vulnerability by sending a crafted 802.11 frame to
the targeted device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to impact the availability of the device
due to authentication failures." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-27 19:39:00 +0000 (Fri, 27 Jan 2017)" );
	script_tag( name: "creation_date", value: "2017-03-02 11:11:21 +0700 (Thu, 02 Mar 2017)" );
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
affected = make_list( "8.2.121.12",
	 "8.4.1.82" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

