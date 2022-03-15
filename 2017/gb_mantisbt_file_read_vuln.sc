CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140285" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-08 15:08:03 +0700 (Tue, 08 Aug 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-09 19:33:00 +0000 (Wed, 09 Aug 2017)" );
	script_cve_id( "CVE-2017-12419" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "MantisBT Arbitrary File Read Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_tag( name: "summary", value: "MantisBT is prone to an arbitrary file read vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a HTTP request and checks the response." );
	script_tag( name: "insight", value: "If, after successful installation of MantisBT on MySQL/MariaDB, the
administrator does not remove the 'admin' directory (as recommended in the 'Post-installation and upgrade tasks'
section of the MantisBT Admin Guide), and the MySQL client has a local_infile setting enabled (in php.ini
mysqli.allow_local_infile, or the MySQL client config file, depending on the PHP setup), an attacker may take
advantage of MySQL's 'connect file read' feature to remotely access files on the MantisBT server." );
	script_tag( name: "affected", value: "MantisBT version 1.x and 2.x." );
	script_tag( name: "solution", value: "Delete the 'admin' directory, disabling mysqli.allow_local_infile in php.ini." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=23173" );
	script_xref( name: "URL", value: "https://mantisbt.org/docs/master/en-US/Admin_Guide/html-desktop/#admin.install.postcommon" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/admin/install.php?install=3";
if(http_vuln_check( port: port, url: url, pattern: "Installing Database", check_header: TRUE )){
	report = "The installer script is accessible at " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

