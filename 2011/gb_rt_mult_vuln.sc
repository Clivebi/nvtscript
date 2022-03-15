if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801857" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)" );
	script_cve_id( "CVE-2011-1007", "CVE-2011-1008" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "RT (Request Tracker) Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43438" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0475" );
	script_xref( name: "URL", value: "http://lists.bestpractical.com/pipermail/rt-announce/2011-February/000186.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "rt_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "RequestTracker/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to bypass certain
  security restrictions or gain knowledge of sensitive information." );
	script_tag( name: "affected", value: "RT (Request Tracker) versions prior to 3.8.9." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when resubmitting form data, which could allow local attackers
  to gain unauthorized access to a user's account.

  - An error when logging SQL queries during a user account transition, which
  could allow attackers to disclose sensitive information." );
	script_tag( name: "solution", value: "Upgrade to RT (Request Tracker) version 3.8.9 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Request Tracker and is prone to
  multiple vulnerabilities." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "rt_tracker" )){
	if(version_is_less( version: vers, test_version: "3.8.9" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.8.9" );
		security_message( port: port, data: report );
	}
}

