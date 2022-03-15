CPE = "cpe:/a:orientdb:orientdb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808755" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_cve_id( "CVE-2015-2913", "CVE-2015-2912" );
	script_bugtraq_id( 76610 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2015-12-31 20:32:00 +0000 (Thu, 31 Dec 2015)" );
	script_tag( name: "creation_date", value: "2016-08-08 16:26:31 +0530 (Mon, 08 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "OrientDB Server 'Studio component' Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with OrientDB
  server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - The JSONP endpoint in the Studio component does not properly
    restrict callback values.

  - The 'server/network/protocol/http/OHttpSessionManager.java' script
    improperly relies on the java.util.Random class for generation of
    random Session ID values." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to conduct cross-site request forgery, and to predict a
  value by determining the internal state of the PRNG in this class.)." );
	script_tag( name: "affected", value: "OrientDB Server Community Edition before
  2.0.15 and 2.1.x before 2.1.1" );
	script_tag( name: "solution", value: "Upgrade to OrientDB Server version 2.0.15,
  or 2.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if( version_is_less( version: dbVer, test_version: "2.0.15" ) ){
	fix = "2.0.15";
	VULN = TRUE;
}
else {
	if(version_is_equal( version: dbVer, test_version: "2.1.0" )){
		fix = "2.1.0";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: fix );
	security_message( data: report, port: dbPort );
	exit( 0 );
}

