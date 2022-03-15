CPE = "cpe:/a:apache:traffic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805129" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-3525" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-01-21 12:21:54 +0530 (Wed, 21 Jan 2015)" );
	script_name( "Apache Traffic Server Synthetic Health Checks Remote DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_traffic_detect.sc" );
	script_mandatory_keys( "apache_trafficserver/installed" );
	script_require_ports( "Services/http_proxy", 8080, 3128, 80 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/60375" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/95495" );
	script_xref( name: "URL", value: "http://mail-archives.apache.org/mod_mbox/trafficserver-users/201407.mbox/%3CBFCEC9C8-1BE9-4DCA-AF9C-B8FE798EEC07@yahoo-inc.com%3E" );
	script_tag( name: "summary", value: "This host is installed with Apache Traffic
  Server is prone to remote denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An unspecified flaw in traffic_cop that
  is triggered as the program fails to restrict access to synthetic health
  checks." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to crash the traffic_manager process." );
	script_tag( name: "affected", value: "Apache Traffic Server version 3.x through
  3.2.5, 4.x before 4.2.1.1, and 5.x before 5.0.1" );
	script_tag( name: "solution", value: "Upgrade to version 4.2.1.1 or 5.0.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(IsMatchRegexp( appVer, "^[3-5]\\." )){
	if(version_in_range( version: appVer, test_version: "3.0", test_version2: "3.2.5" ) || version_in_range( version: appVer, test_version: "4.0", test_version2: "4.2.1" ) || version_is_equal( version: appVer, test_version: "5.0.0" )){
		if(IsMatchRegexp( appVer, "^3\\." )){
			fixVer = "4.2.1.1 or 5.0.1";
		}
		if(IsMatchRegexp( appVer, "^4\\." )){
			fixVer = "4.2.1.1";
		}
		if(IsMatchRegexp( appVer, "^5\\." )){
			fixVer = "5.0.1";
		}
		report = "Installed version: " + appVer + "\n" + "Fixed version: " + fixVer + "\n";
		security_message( port: appPort, data: report );
		exit( 0 );
	}
}

