CPE = "cpe:/a:thekelleys:dnsmasq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103509" );
	script_bugtraq_id( 54353 );
	script_cve_id( "CVE-2012-3411" );
	script_version( "2021-03-26T10:02:15+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-03-26 10:02:15 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2012-07-11 11:18:48 +0200 (Wed, 11 Jul 2012)" );
	script_name( "Dnsmasq <= 2.62 Remote DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_dnsmasq_consolidation.sc" );
	script_mandatory_keys( "thekelleys/dnsmasq/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54353" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=833033" );
	script_xref( name: "URL", value: "http://thekelleys.org.uk/dnsmasq/CHANGELOG" );
	script_tag( name: "summary", value: "Dnsmasq is prone to a Denial of Service (DoS)
  vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause DoS
  conditions through a stream of spoofed DNS queries producing large results." );
	script_tag( name: "affected", value: "Dnsmasq through 2.62." );
	script_tag( name: "solution", value: "Update to version 2.63 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.63" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.63", install_path: location );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

