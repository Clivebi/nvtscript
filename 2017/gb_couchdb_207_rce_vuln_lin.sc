CPE = "cpe:/a:apache:couchdb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107258" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_name( "CouchDB Multiple Vulnerabilities (Linux)" );
	script_cve_id( "CVE-2017-12635", "CVE-2017-12636" );
	script_xref( name: "URL", value: "https://blog.couchdb.org/2017/11/14/apache-couchdb-cve-2017-12635-and-cve-2017-12636/" );
	script_xref( name: "URL", value: "https://justi.cz/security/2017/11/14/couchdb-rce-npm.html" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-11-16 11:20:26 +0700 (Thu, 16 Nov 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_couchdb_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 5984 );
	script_mandatory_keys( "couchdb/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "This host is installed with Apache CouchDB and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 1.7.0 or 2.1.1 or later." );
	script_tag( name: "insight", value: "The vulnerabilities are due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser." );
	script_tag( name: "affected", value: "CouchDB Versions before 1.7.0 and 2.1.1." );
	script_tag( name: "impact", value: "These vulnerabilities can be used to give non-admin users access to arbitrary shell commands on the server as the database system user." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if( IsMatchRegexp( version, "^1\\." ) ){
	if(version_is_less( version: version, test_version: "1.7.0" )){
		fix = "1.7.0";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( version, "^2\\." )){
		if(version_is_less( version: version, test_version: "2.1.1" )){
			fix = "2.1.1";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

