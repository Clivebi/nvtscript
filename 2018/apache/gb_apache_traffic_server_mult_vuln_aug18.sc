CPE = "cpe:/a:apache:traffic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141411" );
	script_version( "2021-06-14T12:08:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 12:08:29 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-30 11:03:19 +0700 (Thu, 30 Aug 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-07 20:31:00 +0000 (Wed, 07 Nov 2018)" );
	script_cve_id( "CVE-2018-1318", "CVE-2018-8004", "CVE-2018-8005", "CVE-2018-8040" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Traffic Server (ATS) Multiple Vulnerabilities (Aug 2018)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_traffic_detect.sc" );
	script_mandatory_keys( "apache_trafficserver/installed" );
	script_tag( name: "summary", value: "Apache Traffic Server (ATS) is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  - CVE-2018-1318: Adding method ACLs in remap.config can cause a segfault when the user makes a
  carefully crafted request.

  - CVE-2018-8004: Multiple HTTP smuggling and cache poisoning issues when clients making malicious
  requests.

  - CVE-2018-8005: When there are multiple ranges in a range request, Apache Traffic Server (ATS)
  will read the entire object from cache. This can cause performance problems with large objects in
  cache.

  - CVE-2018-8040: Pages that are rendered using the ESI plugin can have access to the cookie header
  when the plugin is configured not to allow access." );
	script_tag( name: "affected", value: "Apache Traffic Server version 6.0.0 through 6.2.2 and 7.0.0
  through 7.1.3." );
	script_tag( name: "solution", value: "Update to version 6.2.3, 7.1.4 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2018/q3/197" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2018/q3/199" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2018/q3/198" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2018/q3/196" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.2.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

