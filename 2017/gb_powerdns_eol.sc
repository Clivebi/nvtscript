if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113017" );
	script_version( "2020-12-09T13:05:49+0000" );
	script_tag( name: "last_modification", value: "2020-12-09 13:05:49 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2017-10-16 13:11:12 +0200 (Mon, 16 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "PowerDNS Products End of Life (EOL) Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "pdns_version.sc" );
	script_mandatory_keys( "powerdns/recursor_or_authoritative_server/installed" );
	script_tag( name: "summary", value: "The version of the PowerDNS product on the remote host
  has reached the End of Life (EOL) and should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of a PowerDNS product is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise
  the security of this host." );
	script_tag( name: "solution", value: "Update the version of the PowerDNS product on the remote host to a still
  supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_xref( name: "URL", value: "https://doc.powerdns.com/authoritative/appendices/EOL.html" );
	script_xref( name: "URL", value: "https://doc.powerdns.com/recursor/appendices/EOL.html" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:powerdns:authoritative_server",
	 "cpe:/a:powerdns:recursor" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!infos = get_app_version_and_proto( cpe: cpe, port: port )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
if(ret = product_reached_eol( cpe: cpe, version: version )){
	if( ContainsString( cpe, "recursor" ) ) {
		app = "PowerDNS Recursor";
	}
	else {
		if( ContainsString( cpe, "authoritative_server" ) ) {
			app = "Authoritative Server";
		}
		else {
			app = "PowerDNS";
		}
	}
	report = build_eol_message( name: app, cpe: cpe, version: version, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

