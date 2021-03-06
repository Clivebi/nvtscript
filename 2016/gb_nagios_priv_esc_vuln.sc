CPE = "cpe:/a:nagios:nagios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106474" );
	script_version( "$Revision: 12149 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-15 10:22:34 +0700 (Thu, 15 Dec 2016)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-8641" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Nagios Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "nagios_detect.sc" );
	script_mandatory_keys( "nagios/installed" );
	script_tag( name: "summary", value: "Nagios is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Nagios startup script, run by root, is insecurely giving owner of file
to nagios. If the Nagios user symlink $NagiosRunFile to a file that he has no access to, at startup or reboot of
the nagios daemon, the init script will give him ownership of the linked file." );
	script_tag( name: "impact", value: "A local attacker may gain privileged access to files." );
	script_tag( name: "affected", value: "Nagios 4.2.2 and before." );
	script_tag( name: "solution", value: "Update to version 4.2.3 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40774/" );
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
if(version_is_less( version: version, test_version: "4.2.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

