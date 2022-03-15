CPE = "cpe:/h:fortinet:fortianalyzer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105202" );
	script_cve_id( "CVE-2014-0224", "CVE-2014-0221", "CVE-2014-0195" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_name( "Fortinet FortiAnalyzer Multiple Vulnerabilities in OpenSSL (FG-IR-14-018)" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-14-018" );
	script_tag( name: "impact", value: "CVE-2014-0224 may allow an attacker with a privileged network position (man-in-the-middle) to decrypt SSL encrypted
communications.

CVE-2014-0221 may allow an attacker to crash a DTLS client with an invalid handshake.

CVE-2014-0195 can result in a buffer overrun attack by sending invalid DTLS fragments to an OpenSSL DTLS client or server.

CVE-2014-0198 and CVE-2010-5298 may allow an attacker to cause a denial of service under certain conditions, when SSL_MODE_RELEASE_BUFFERS
is enabled.

CVE-2014-3470 may allow an attacker to trigger a denial of service in SSL clients when anonymous ECDH ciphersuites are enabled. This issue
does not affect Fortinet products.

CVE-2014-0076 can be used to discover ECDSA nonces on multi-user systems by exploiting timing attacks in CPU L3 caches. This does not apply
to Fortinet products." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to FortiAnalyzer 5.2.0/5.0.7 (build 321) or later." );
	script_tag( name: "summary", value: "Fortinet FortiAnalyzer is prone to multiple vulnerabilities in
  OpenSSL." );
	script_tag( name: "affected", value: "FortiAnalyzer < 5.2.0/5.0.7." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-02-11 12:17:13 +0100 (Wed, 11 Feb 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_fortianalyzer_version.sc" );
	script_mandatory_keys( "fortianalyzer/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
version = get_app_version( cpe: CPE );
if(!version){
	version = get_kb_item( "fortianalyzer/version" );
}
if(!version){
	exit( 0 );
}
if( IsMatchRegexp( version, "^5\\.2" ) ) {
	fix = "5.2.0";
}
else {
	if(IsMatchRegexp( version, "^5\\.0" )){
		fix = "5.0.7";
		build = get_kb_item( "fortianalyzer/build" );
		if(build){
			if(int( build ) >= 321){
				exit( 99 );
			}
		}
	}
}
if(!fix){
	exit( 0 );
}
if(version_is_less( version: version, test_version: fix )){
	model = get_kb_item( "fortianalyzer/model" );
	if(!isnull( model )){
		report = "Model:             " + model + "\n";
	}
	report += "Installed Version: " + version + "\nFixed Version:     " + fix + "\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

