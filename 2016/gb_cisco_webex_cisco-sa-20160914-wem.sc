CPE = "cpe:/a:cisco:webex_meetings_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106252" );
	script_version( "2020-11-25T14:53:04+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 14:53:04 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-09-16 12:38:55 +0700 (Fri, 16 Sep 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-1482" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Webex Meetings Server Remote Command Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_webex_meetings_server_detect.sc" );
	script_mandatory_keys( "cisco/webex/meetings_server/detected" );
	script_tag( name: "summary", value: "A vulnerability in Cisco Webex Meetings Server could allow an
  unauthenticated, remote attacker to bypass security restrictions on a host located in a DMZ and inject arbitrary
  commands on a targeted system." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient sanitization of user-supplied data
  processed by the affected software. An attacker could exploit this vulnerability by injecting arbitrary commands
  into existing application scripts running on a targeted device located in a DMZ." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary
  commands on the device with elevated privileges." );
	script_tag( name: "affected", value: "Cisco Webex Meetings Server version 2.0, 2.5 and 2.6." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160914-wem" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^2\\.[056]" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

