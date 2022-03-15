CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100668" );
	script_version( "2021-03-10T13:54:33+0000" );
	script_tag( name: "last_modification", value: "2021-03-10 13:54:33 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "creation_date", value: "2010-06-04 13:05:19 +0200 (Fri, 04 Jun 2010)" );
	script_bugtraq_id( 40502 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-0742" );
	script_name( "OpenSSL Cryptographic Message Syntax Memory Corruption Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40502" );
	script_xref( name: "URL", value: "http://www.openssl.org/news/secadv_20100601.txt" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_openssl_consolidation.sc" );
	script_mandatory_keys( "openssl/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "OpenSSL is prone to a remote memory-corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker can exploit this issue by supplying specially crafted
  structures to a vulnerable application that uses the affected library." );
	script_tag( name: "impact", value: "Successfully exploiting this issue can allow the attacker to execute
  arbitrary code. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Versions of OpenSSL 0.9.8.h through 0.9.8n and OpenSSL 1.0.x prior to
  1.0.0a are affected. Note that Cryptographic Message Syntax (CMS)
  functionality is only enabled by default in OpenSSL versions 1.0.x." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^0\\.9\\.([0-7]([^0-9]|$)|8([^a-z0-9]|[a-n]|$))" ) || IsMatchRegexp( vers, "^1\\.0\\.0(-beta|$)" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.8o/1.0.0a", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

