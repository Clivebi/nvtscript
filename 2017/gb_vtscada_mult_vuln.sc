CPE = "cpe:/a:trihedral:vtscada";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106906" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-23 16:17:12 +0700 (Fri, 23 Jun 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:28:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2017-6043", "CVE-2017-6045", "CVE-2017-6053" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "VTScada Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_vtscada_detect.sc" );
	script_mandatory_keys( "vtscada/detected" );
	script_tag( name: "summary", value: "VTScada is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "VTScada is prone to multiple vulnerabilities:

  - The client does not properly validate the input or limit the amount of resources that are utilized by an
attacker, which can be used to consume more resources than are available. (CVE-2017-6043)

  - Some files are exposed within the web server application to unauthenticated users. These files may contain
sensitive configuration information. (CVE-2017-6045)

  - A cross-site scripting vulnerability may allow JavaScript code supplied by the attacker to execute within the
user's browser. (CVE-2017-6053)" );
	script_tag( name: "affected", value: "VTScada Versions prior to 11.2.26" );
	script_tag( name: "solution", value: "Update to version 11.2.26 or later." );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-17-164-01" );
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
if(version_is_less( version: version, test_version: "11.2.26" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.2.26" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

