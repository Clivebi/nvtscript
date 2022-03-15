if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113024" );
	script_version( "2020-12-09T13:05:49+0000" );
	script_tag( name: "last_modification", value: "2020-12-09 13:05:49 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2017-10-16 14:57:58 +0200 (Mon, 16 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "IBM Domino End of Life (EOL) Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hcl_domino_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "hcl/domino/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "The IBM Domino version on the remote host
  has reached the End of Life (EOL) and should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of IBM Domino is not
  receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host." );
	script_tag( name: "solution", value: "Update the IBM Domino version on the remote
  host to a still supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_xref( name: "URL", value: "https://www-01.ibm.com/software/support/lifecycleapp/PLCSearch.wss?q=lotus+domino&ibm-search=Search" );
	exit( 0 );
}
CPE = "cpe:/a:ibm:lotus_domino";
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: "IBM Domino", cpe: CPE, version: version, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

