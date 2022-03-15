CPE = "cpe:/a:extreme:extremexos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106428" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2016-0800" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Extreme ExtremeXOS DROWN Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_extremeos_snmp_detect.sc" );
	script_mandatory_keys( "extremexos/detected" );
	script_tag( name: "summary", value: "Extreme ExtremeXOS is prone to the OpenSSL 'DROWN' vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The SSLv2 protocol requires a server to send a ServerVerify message before
establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to
decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a 'DROWN' attack.

All SSLv2 ciphers are disabled, but SSLv2 protocol is enabled on EXOS. Since EXOS is vulnerable to CVE-2015-3197,
SSLv2 ciphers can still be negotiated, which renders the switch vulnerable." );
	script_tag( name: "impact", value: "Cross-protocol attack that could lead to decryption of TLS sessions." );
	script_tag( name: "affected", value: "Versions before 16.2.1 and 21.1.2." );
	script_tag( name: "solution", value: "Upgrade to 16.2.1, 21.1.2, 22.1.1 or later." );
	script_xref( name: "URL", value: "https://gtacknowledge.extremenetworks.com/articles/Vulnerability_Notice/VN-2016-004" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "16.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "16.2.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^21\\.1\\.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "21.1.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

