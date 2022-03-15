CPE = "cpe:/a:gnome:evolution";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800254" );
	script_version( "$Revision: 14033 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 34109, 34100 );
	script_cve_id( "CVE-2009-0582", "CVE-2009-0587" );
	script_name( "Evolution Data Server Multiple Integer Overflow Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_evolution_data_server_detect.sc" );
	script_mandatory_keys( "Evolution/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34286" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1021845" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2009/03/12/2" );
	script_xref( name: "URL", value: "http://mail.gnome.org/archives/release-team/2009-March/msg00096.html" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes
  through long string that is converted to a base64 representation and
  can cause a client crash via NTLM authentication type 2 packet with a
  length value that exceeds the amount of packet data." );
	script_tag( name: "affected", value: "Evolution Data Server version 2.24.5 and prior.
  Evolution Data Server version in range 2.25.x to 2.25.92." );
	script_tag( name: "insight", value: "- bug in Camel library while processing NTLM SASL packets.

  - bug in glib library while encoding and decoding Base64 data." );
	script_tag( name: "summary", value: "This host is installed with Evolution Data Server and is prone to
  multiple integer overflow vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to version 2.26 or later." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: ver, test_version: "2.25", test_version2: "2.25.92" ) || version_is_less_equal( version: ver, test_version: "2.24.5" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.26" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

