if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800472" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-0636", "CVE-2010-0637", "CVE-2010-0638" );
	script_bugtraq_id( 38053 );
	script_name( "WebCalendar Multiple CSS and CSRF Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38222" );
	script_xref( name: "URL", value: "http://holisticinfosec.org/content/view/133/45/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "webcalendar_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "webcalendar/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to conduct cross-site scripting
  and request forgery attacks." );
	script_tag( name: "affected", value: "WebCalendar version 1.2.0 and prior." );
	script_tag( name: "insight", value: "- Input passed to the 'tab' parameter in 'users.php' is not properly
  sanitised before being returned to the user.

  - Input appended to the URL after 'day.php', 'month.php', and 'week.php'
  is not properly sanitised before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests. This can be
  exploited to delete an event, ban an IP address from posting, or change the
  administrative password if a logged-in administrative user visits a malicious web site." );
	script_tag( name: "solution", value: "Upgrade to WebCalendar version 1.2.1 or later." );
	script_tag( name: "summary", value: "The host is running WebCalendar and is prone to multiple CSS and
  CSRF Vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
wcport = http_get_port( default: 80 );
wcver = get_kb_item( "www/" + wcport + "/webcalendar" );
if(isnull( wcver )){
	exit( 0 );
}
wcver = eregmatch( pattern: "^(.+) under (/.*)$", string: wcver );
if(!isnull( wcver[1] )){
	if(version_is_less_equal( version: wcver[1], test_version: "1.2.0" )){
		report = report_fixed_ver( installed_version: wcver[1], vulnerable_range: "Less than or equal to 1.2.0" );
		security_message( port: wcport, data: report );
	}
}

