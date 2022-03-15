CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106665" );
	script_cve_id( "CVE-2017-3854" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_name( "Cisco Meshed Wireless LAN Controller Impersonation Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-wlc-mesh" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the mesh code of Cisco Wireless LAN Controller (WLC)
software could allow an unauthenticated, remote attacker to impersonate a WLC in a meshed topology." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient authentication of the parent access
point in a mesh configuration. An attacker could exploit this vulnerability by forcing the target system to
disconnect from the correct parent access point and reconnect to a rogue access point owned by the attacker." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to control the traffic flowing through
the impacted access point or take full control of the target system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-14 12:12:00 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-17 10:43:42 +0700 (Fri, 17 Mar 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wlc_consolidation.sc" );
	script_mandatory_keys( "cisco/wlc/detected", "cisco/wlc/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!model = get_kb_item( "cisco/wlc/model" )){
	exit( 0 );
}
if(!IsMatchRegexp( model, "25[0-9][0-9]" ) && !IsMatchRegexp( model, "55[0-9][0-9]" ) && !IsMatchRegexp( model, "85[0-9][0-9]" ) && !IsMatchRegexp( model, "AIR-CTVM" )){
	exit( 99 );
}
affected = make_list( "3.1.105.0",
	 "3.1.111.0",
	 "3.1.59.24",
	 "3.2.116.21",
	 "3.2.150.10",
	 "3.2.150.6",
	 "3.2.171.5",
	 "3.2.171.6",
	 "3.2.185.0",
	 "3.2.193.5",
	 "3.2.195.10",
	 "3.2.78.0",
	 "3.6.0E",
	 "4.0.108",
	 "4.0.155.0",
	 "4.0.155.5",
	 "4.0.179.11",
	 "4.0.179.8",
	 "4.0.196",
	 "4.0.206.0",
	 "4.0.217.0",
	 "4.0.219.0",
	 "4.1.171.0",
	 "4.1.181.0",
	 "4.1.185.0",
	 "4.2.112.0",
	 "4.2.117.0",
	 "4.2.130.0",
	 "4.2.173.0",
	 "4.2.174.0",
	 "4.2.176.0",
	 "4.2.182.0",
	 "4.2.61.0",
	 "4.2.99.0",
	 "5.0.148.0",
	 "5.0.148.2",
	 "5.1.151.0",
	 "5.1.152.0",
	 "5.1.160.0",
	 "5.2.157.0",
	 "5.2.169.0",
	 "6.0182.0",
	 "6.0188.0",
	 "6.0196.0",
	 "6.0199.4",
	 "6.0202.0",
	 "7.0116.0",
	 "7.0220.0",
	 "7.0240.0",
	 "7.0250.0",
	 "7.0252.0",
	 "7.098.0",
	 "7.098.218",
	 "7.191.0",
	 "7.2103.0",
	 "7.3.101.0",
	 "7.3.103.8",
	 "7.3.112",
	 "7.4.1.1",
	 "7.4.100",
	 "7.4.100.60",
	 "7.4.110.0",
	 "7.4.121.0",
	 "7.41.19",
	 "7.41.54",
	 "7.4140.0",
	 "7.5.102.0",
	 "7.5.102.11",
	 "7.6.1.62",
	 "7.6.100.0",
	 "7.6.110.0",
	 "7.6.120.0",
	 "7.6.130.0",
	 "8.0.0",
	 "8.0.0.30220.385",
	 "8.0.100",
	 "8.0.115.0",
	 "8.0.120.0",
	 "8.0.121.0",
	 "8.0.72.140",
	 "8.1.0",
	 "8.1.104.37",
	 "8.1.111.0",
	 "8.1.122.0",
	 "8.1.130.0" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

