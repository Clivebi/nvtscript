CPE = "cpe:/a:cisco:meeting_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106371" );
	script_cve_id( "CVE-2016-6448" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco Meeting Server Session Description Protocol Media Lines Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-cms1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 2.0.3 or later." );
	script_tag( name: "summary", value: "A vulnerability in the Session Description Protocol (SDP) parser of Cisco
Meeting Server could allow an unauthenticated, remote attacker to execute arbitrary code on an affected system." );
	script_tag( name: "insight", value: "The vulnerability exists because the affected software performs incomplete
input validation of the size of media lines in session descriptions. An attacker could exploit this vulnerability
by sending crafted packets to the SDP parser on an affected system." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to cause a buffer overflow
condition on an affected system, which could allow the attacker to execute arbitrary code on the system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-11-03 14:19:37 +0700 (Thu, 03 Nov 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_meeting_server_snmp_detect.sc" );
	script_mandatory_keys( "cisco/meeting_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "1.8.0",
	 "1.8.15",
	 "1.9.0",
	 "1.9.2",
	 "2.0.0" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.0.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

