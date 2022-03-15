if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103349" );
	script_bugtraq_id( 50742 );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Support Incident Tracker 'translate.php' Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50742" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520577" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-30 11:40:15 +0100 (Wed, 30 Nov 2011)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "support_incident_tracker_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sit/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Support Incident Tracker is prone to a remote code-execution
  vulnerability because the application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue will allow attackers to execute arbitrary PHP
  code within the context of the affected application." );
	script_tag( name: "affected", value: "Support Incident Tracker 3.45 to 3.65 is vulnerable. Prior versions
  may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "support_incident_tracker" )){
	if(version_in_range( version: vers, test_version: "3.45", test_version2: "3.65" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "3.45 - 3.65" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

