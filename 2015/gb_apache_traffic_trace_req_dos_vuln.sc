CPE = "cpe:/a:apache:traffic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805128" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-10022" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-01-21 11:00:56 +0530 (Wed, 21 Jan 2015)" );
	script_name( "Apache Traffic Server HTTP TRACE Request Remote DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_traffic_detect.sc" );
	script_mandatory_keys( "apache_trafficserver/installed" );
	script_require_ports( "Services/http_proxy", 8080, 3128, 80 );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/TS-3223" );
	script_xref( name: "URL", value: "http://mail-archives.apache.org/mod_mbox/trafficserver-users/201412.mbox/thread" );
	script_tag( name: "summary", value: "This host is installed with Apache Traffic
  Server is prone to remote denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to an improper handling HTTP
  TRACE requests with a 'Max-Forwards' header value of '0'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to crash the traffic_manager process." );
	script_tag( name: "affected", value: "Apache Traffic Server version 5.1.x
  before 5.1.2" );
	script_tag( name: "solution", value: "Upgrade to version 5.1.2 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!appPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!appVer = get_app_version( cpe: CPE, port: appPort )){
	exit( 0 );
}
if(IsMatchRegexp( appVer, "^5\\.1" )){
	if(version_in_range( version: appVer, test_version: "5.1.0", test_version2: "5.1.1" )){
		report = "Installed version: " + appVer + "\n" + "Fixed version: 5.1.2 \n";
		security_message( port: appPort, data: report );
		exit( 0 );
	}
}

