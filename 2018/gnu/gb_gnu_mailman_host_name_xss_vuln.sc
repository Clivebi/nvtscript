CPE = "cpe:/a:gnu:mailman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813268" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_cve_id( "CVE-2018-0618" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-06 20:15:00 +0000 (Wed, 06 May 2020)" );
	script_tag( name: "creation_date", value: "2018-07-27 12:20:44 +0530 (Fri, 27 Jul 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "GNU Mailman 'host_name' Cross-Site Scripting vulnerability" );
	script_tag( name: "summary", value: "This host is installed with mailman and
  is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an input validation
  error in 'host_name' field." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct XSS attack." );
	script_tag( name: "affected", value: "GNU Mailman version 2.1.26 and prior." );
	script_tag( name: "solution", value: "Upgrade to GNU Mailman 2.1.27 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN00846677/index.html" );
	script_xref( name: "URL", value: "https://mail.python.org/pipermail/mailman-announce/2018-June/000236.html" );
	script_xref( name: "URL", value: "https://www.gnu.org/software/mailman" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mailman_detect.sc" );
	script_mandatory_keys( "gnu_mailman/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!cyPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: cyPort, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "2.1.27" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.1.27 or later.", install_path: path );
	security_message( data: report, port: cyPort );
	exit( 0 );
}

