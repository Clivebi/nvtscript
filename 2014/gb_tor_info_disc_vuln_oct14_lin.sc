CPE = "cpe:/a:tor:tor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804934" );
	script_version( "$Revision: 11867 $" );
	script_cve_id( "CVE-2014-5117" );
	script_bugtraq_id( 68968 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-10-14 10:45:19 +0530 (Tue, 14 Oct 2014)" );
	script_name( "Tor 'Relay Early' Traffic Confirmation Attack Vunerability oct14 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Tor browser
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to an error
  in the handling of sequences of Relay and Relay Early commands." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to manipulate protocol headers and perform traffic confirmation attack." );
	script_tag( name: "affected", value: "Tor browser before 0.2.4.23 and 0.2.5
  before 0.2.5.6-alpha on Linux" );
	script_tag( name: "solution", value: "Upgrade to version 0.2.4.23 or
  0.2.5.6-alpha or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/95053" );
	script_xref( name: "URL", value: "https://blog.torproject.org/blog/tor-security-advisory-relay-early-traffic-confirmation-attack" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_tor_detect_lin.sc" );
	script_mandatory_keys( "Tor/Linux/Ver" );
	script_xref( name: "URL", value: "https://www.torproject.org" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!torVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(( version_is_less( version: torVer, test_version: "0.2.4.23" ) ) || ( version_in_range( version: torVer, test_version: "0.2.5", test_version2: "0.2.5.5" ) )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

