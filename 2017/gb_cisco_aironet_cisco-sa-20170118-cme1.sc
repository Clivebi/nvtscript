CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106625" );
	script_cve_id( "CVE-2016-9220" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_name( "Cisco Mobility Express 2800 and 3800 802.11 Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-cme1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 8.2.141.0 or later." );
	script_tag( name: "summary", value: "A vulnerability in 802.11 ingress packet processing of the Cisco Mobility
Express 2800 and 3800 Access Points could allow an unauthenticated, adjacent attacker to cause the connection
table to be full of invalid connections and be unable to process new incoming requests." );
	script_tag( name: "insight", value: "The vulnerability is due to lack of proper error handling when the 802.11
frame is received with an unexpected status code. An attacker could exploit this vulnerability by sending a
crafted 802.11 frame to the targeted device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to impact the availability of the device
due to the connection table being filled with invalid connections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-27 02:59:00 +0000 (Fri, 27 Jan 2017)" );
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
if(version == "8.2.130.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.2.141.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

