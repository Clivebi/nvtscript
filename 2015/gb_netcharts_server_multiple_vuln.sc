CPE = "cpe:/a:visual_mining:netcharts_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805643" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-4031", "CVE-2015-4032" );
	script_bugtraq_id( 74788 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-06-03 12:12:21 +0530 (Wed, 03 Jun 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NetCharts Server Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with NetCharts
  Server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is installed with vulnerable version or not." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The projectContents.jsp script in developer tools does not properly verify
    or sanitize user-uploaded files.

  - The saveFile.jsp script in developer installation not properly sanitizing
    user input, specifically path traversal style attacks" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to write to arbitrary files via unspecified vectors, rename files
  and execute arbitrary PHP code." );
	script_tag( name: "affected", value: "Visual Mining NetChart Server" );
	script_tag( name: "solution", value: "As a workaround restrict interaction with
  the service to trusted machines. Only the clients and servers that have a
  legitimate procedural relationship with the service should be permitted to
  communicate with it." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-15-238/" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-15-237/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_netcharts_server_detect.sc" );
	script_mandatory_keys( "netchart/installed" );
	script_require_ports( "Services/www", 8001 );
	script_xref( name: "URL", value: "http://www.visualmining.com/nc-server/" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ncPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ncVer = get_app_version( cpe: CPE, port: ncPort )){
	exit( 0 );
}
if(version_is_equal( version: ncVer, test_version: "7.0.1" )){
	report = "Installed Version: " + ncVer + "\n" + "Fixed Version:     " + "Workaround" + "\n";
	security_message( port: ncPort, data: report );
	exit( 0 );
}

