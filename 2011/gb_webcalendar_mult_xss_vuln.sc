if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802305" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WebCalendar Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/102785/SSCHADV2011-008.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "webcalendar_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "webcalendar/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "WebCalendar versions 1.2.3 and prior." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied
  input in various scripts, which allows attackers to execute arbitrary HTML and
  script code on the web server." );
	script_tag( name: "solution", value: "Upgrade to WebCalendar versions 1.2.4 or later." );
	script_tag( name: "summary", value: "This host is running WebCalendar and is prone to multiple cross
  site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "webcalendar" )){
	if(version_is_less_equal( version: vers, test_version: "1.2.3" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 1.2.3" );
		security_message( port: port, data: report );
	}
}

