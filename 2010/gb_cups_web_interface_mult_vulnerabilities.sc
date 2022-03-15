CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100687" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2010-06-22 12:10:21 +0200 (Tue, 22 Jun 2010)" );
	script_bugtraq_id( 40897, 40889 );
	script_cve_id( "CVE-2010-1748", "CVE-2010-0540" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_name( "CUPS Web Interface Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_require_ports( "Services/www", 631 );
	script_mandatory_keys( "CUPS/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40897" );
	script_xref( name: "URL", value: "http://cups.org/articles.php?L596" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "CUPS Web Interface is prone to Multiple Vulnerabilities.

  1. A remote information-disclosure vulnerability. This
  issue affects the CUPS web interface component.

  Remote attackers can exploit this issue to obtain sensitive
  information that may lead to further attacks.

  2. A cross-site request-forgery vulnerability.

  Attackers can exploit this issue to perform certain administrative
  actions and gain unauthorized access to the affected application." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(!IsMatchRegexp( vers, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
path = infos["location"];
if(version_is_less( version: vers, test_version: "1.4.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.4", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

