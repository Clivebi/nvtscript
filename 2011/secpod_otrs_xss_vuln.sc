CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902352" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2010-4071" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)" );
	script_name( "Open Ticket Request System (OTRS) 'AgentTicketZoom' Cross-site scripting Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to insert arbitrary HTML and
script code, which will be executed in a user's browser session in the
context of an affected site when malicious data is being viewed." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to input passed via HTML e-mails is not properly sanitised in
AgentTicketZoom before being displayed to the user." );
	script_tag( name: "solution", value: "Upgrade to Open Ticket Request System (OTRS) version 2.4.9 or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running Open Ticket Request System (OTRS) and is prone to
Cross-site scripting vulnerability." );
	script_tag( name: "affected", value: "Open Ticket Request System (OTRS) version 2.4.x before 2.4.9." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41978" );
	script_xref( name: "URL", value: "http://otrs.org/advisory/OSA-2010-03-en/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_in_range( version: vers, test_version: "2.4.0", test_version2: "2.4.8" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "2.4.0 - 2.4.8" );
		security_message( port: port, data: report );
	}
}

