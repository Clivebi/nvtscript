CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807450" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2016-2572" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-03-03 11:34:15 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Squid 'http.cc' Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is running Squid and is prone
  to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in 'http.cc'
  script relies on the HTTP status code after a response-parsing failure." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  HTTP servers to cause a denial of service." );
	script_tag( name: "affected", value: "Squid version 4.x before 4.0.7 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Squid version 4.0.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://access.redhat.com/security/cve/cve-2016-2572" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2016_2.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "squid_proxy_server/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 3128, 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!squidPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!squidVer = get_app_version( cpe: CPE, port: squidPort )){
	exit( 0 );
}
if(IsMatchRegexp( squidVer, "^4\\." )){
	if(version_in_range( version: squidVer, test_version: "4.0.0", test_version2: "4.0.6" )){
		report = report_fixed_ver( installed_version: squidVer, fixed_version: "4.0.7" );
		security_message( data: report, port: squidPort );
		exit( 0 );
	}
}

