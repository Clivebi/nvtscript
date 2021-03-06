CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106037" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-22 13:45:14 +0200 (Sat, 22 Aug 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-4321" );
	script_bugtraq_id( 76325 );
	script_name( "Cisco ASA uRFP Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	script_tag( name: "summary", value: "Cisco ASA is prone to a Unicast
Reverse Path Forwarding Bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to incorrect uRPF
validation where IP packets from an outside interface, whose IP address is both in
the ASA routing table and associated with an internal interface, are not dropped." );
	script_tag( name: "impact", value: "An unauthenticated, remote attacker could exploit
this vulnerability by sending spoofed IP packets to a targeted ASA in a subnet range
that should be dropped. An exploit could allow the attacker to bypass uRPF validation
on the ASA which would cause packets to be incorrectly forwarded on the internal network." );
	script_tag( name: "affected", value: "Version 9.3 and 9.4" );
	script_tag( name: "solution", value: "Apply the appropriate updates from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=40440" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
compver = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(( revcomp( a: compver, b: "9.4.1.103" ) <= 0 ) && ( revcomp( a: compver, b: "9.3" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.4(1.103)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

