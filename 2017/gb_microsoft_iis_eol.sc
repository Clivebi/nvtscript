CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108114" );
	script_version( "2020-11-25T11:26:55+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-03-31 08:00:00 +0200 (Fri, 31 Mar 2017)" );
	script_name( "Microsoft Internet Information Services (IIS) End Of Life Detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_dependencies( "gb_ms_iis_detect_win.sc", "secpod_ms_iis_detect.sc" );
	script_mandatory_keys( "IIS/installed" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/lifecycle/search?alpha=Microsoft%20Internet%20Information%20Services" );
	script_tag( name: "summary", value: "The Microsoft Internet Information Services (IIS) version on the remote host has reached
  the end of life and should not be used anymore." );
	script_tag( name: "impact", value: "An end of life version of Microsoft IIS is not receiving
  any security updates from the vendor. Unfixed security vulnerabilities might be leveraged by an
  attacker to compromise the security of this host." );
	script_tag( name: "solution", value: "The Microsoft IIS version is tightly coupled to the
  operation system on the remote host. Updating the operation system to a supported version is required." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: "Internet Information Services (IIS)", cpe: CPE, version: version, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

