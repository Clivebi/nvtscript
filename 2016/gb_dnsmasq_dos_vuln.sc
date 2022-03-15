CPE = "cpe:/a:thekelleys:dnsmasq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106095" );
	script_version( "2021-03-26T10:02:15+0000" );
	script_tag( name: "last_modification", value: "2021-03-26 10:02:15 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-06-15 12:45:27 +0700 (Wed, 15 Jun 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2015-8899" );
	script_name( "Dnsmasq 2.73 - 2.75 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_dnsmasq_consolidation.sc" );
	script_mandatory_keys( "thekelleys/dnsmasq/detected" );
	script_xref( name: "URL", value: "http://www.thekelleys.org.uk/dnsmasq/CHANGELOG" );
	script_xref( name: "URL", value: "http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2016q2/010479.html" );
	script_tag( name: "summary", value: "Dnsmasq is prone to a Denial of Service (DoS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "Dnsmasq crashes when an A or AAAA record is defined
  locally, in a hosts file, and an upstream server sends a reply that the same name is
  empty." );
	script_tag( name: "impact", value: "A remote attacker may cause a DoS condition." );
	script_tag( name: "affected", value: "Dnsmasq 2.73 through 2.75." );
	script_tag( name: "solution", value: "Update to version 2.76 or later." );
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
if(version_in_range( version: version, test_version: "2.73", test_version2: "2.75" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.76", install_path: location );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

