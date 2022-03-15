CPE = "cpe:/a:orientdb:orientdb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808754" );
	script_version( "$Revision: 11811 $" );
	script_cve_id( "CVE-2015-2918" );
	script_bugtraq_id( 76610 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-10 11:55:00 +0200 (Wed, 10 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-08 18:00:11 +0530 (Mon, 08 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "OrientDB Server Clickjacking Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with OrientDB
  server and is prone to Clickjacking vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an OrientDB Studio
  web management interface does not by default enforce the same-origin policy
  in X-Frame-Options response headers." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to conduct clickjacking attacks.)." );
	script_tag( name: "affected", value: "OrientDB Server Community Edition before
  2.0.15 and 2.1.x before 2.1.1" );
	script_tag( name: "solution", value: "As a workaround use the command line
  argument when starting the server:
  Dnetwork.http.additionalResponseHeaders='X-FRAME-OPTIONS: DENY' or
  add this value to the server's orientdb-server-config.xml file. or
  Disable OrientDB Studio." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/845332" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_orientdb_server_detect.sc" );
	script_mandatory_keys( "OrientDB/Installed" );
	script_require_ports( "Services/www", 2480 );
	script_xref( name: "URL", value: "http://orientdb.com/" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!dbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dbVer = get_app_version( cpe: CPE, port: dbPort )){
	exit( 0 );
}
if(version_is_less( version: dbVer, test_version: "2.0.15" ) || version_is_equal( version: dbVer, test_version: "2.1.0" )){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Workaround" );
	security_message( data: report, port: dbPort );
	exit( 0 );
}

