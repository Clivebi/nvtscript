CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103939" );
	script_bugtraq_id( 58162 );
	script_cve_id( "CVE-2010-5107" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_name( "OpenSSH Denial of Service Vulnerability" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-04-09 12:16:30 +0200 (Wed, 09 Apr 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/58162" );
	script_tag( name: "impact", value: "Exploiting this issue allows remote attackers to trigger denial-of-
  service conditions." );
	script_tag( name: "vuldetect", value: "Compare the version retrieved from the banner with the affected range." );
	script_tag( name: "insight", value: "The default configuration of OpenSSH through 6.1 enforces a fixed
  time limit between establishing a TCP connection and completing a login, which makes it easier for
  remote attackers to cause a denial of service (connection-slot exhaustion) by periodically making
  many new TCP connections." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "OpenSSH is prone to a remote denial-of-service vulnerability." );
	script_tag( name: "affected", value: "OpenSSH 6.1 and prior." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "6.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

