CPE = "cpe:/a:apachefriends:xampp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900527" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-6498", "CVE-2008-6499" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "XAMPP Multiple CSRF Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xampp_detect.sc" );
	script_mandatory_keys( "xampp/detected" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute crafted malicious
  queries in the vulnerable parameters or can change admin authentication data
  via crafted CSRF queries." );
	script_tag( name: "affected", value: "XAMPP version 1.6.8 or prior on all platforms." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Lack of input validation checking for the user-supplied data provided
    to 'security/xamppsecurity.php' which lets change admin password through
    CSRF attack.

  - Input passed to some certain parameters like 'dbserver', 'host', 'password',
    'database' and 'table' in not properly sanitised before being returned to a
    user." );
	script_tag( name: "solution", value: "Upgrade to XAMPP version 1.7.3 or later." );
	script_tag( name: "summary", value: "The host is installed with XAMPP and is prone to multiple
  cross-site request forgery vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32134" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7384" );
	script_xref( name: "URL", value: "http://securityreason.com/securityalert/5434" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "1.6.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

