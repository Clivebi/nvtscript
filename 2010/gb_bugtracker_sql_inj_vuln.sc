if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801279" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)" );
	script_bugtraq_id( 42784 );
	script_cve_id( "CVE-2010-3188" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "BugTracker.NET 'search.aspx' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41150" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61434" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/513385/100/0/threaded" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/btnet/files/btnet_3_4_4_release_notes.txt/view" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_bugtracker_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "BugTrackerNET/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information." );
	script_tag( name: "affected", value: "BugTracker.NET version 3.4.3 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input via the
  custom field parameters to 'search.aspx' that allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to BugTracker.NET version 3.4.4 or later." );
	script_tag( name: "summary", value: "The host is running BugTracker.NET and is prone to SQL injection
  vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(ver = get_version_from_kb( port: port, app: "btnet" )){
	if(version_is_less( version: ver, test_version: "3.4.3" )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "3.4.3" );
		security_message( port: port, data: report );
	}
}

