if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106286" );
	script_version( "$Revision: 12313 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-22 10:06:54 +0700 (Thu, 22 Sep 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2015-3193", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196", "CVE-2015-1794" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco IP Phone 8800 Series Multiple Vulnerabilities in OpenSSL" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_ip_phone_detect.sc" );
	script_mandatory_keys( "cisco/ip_phone/model" );
	script_tag( name: "summary", value: "On December 3, 2015, the OpenSSL Project released a security advisory
detailing five vulnerabilities. Cisco IP Phone 8800 Series incorporate a version of the OpenSSL package affected
by one or more vulnerabilities that could allow an unauthenticated, remote attacker to cause a denial of service
(DoS) condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple OpenSSL vulnerabilities affecting Cisco IP Phone 8800 Series:

  - A vulnerability in the Montgomery multiplication module of OpenSSL could allow an unauthenticated, remote
attacker to cause the library to produce unexpected and possibly weak cryptographic output (CVE-2015-3193).

  - A vulnerability in OpenSSL could allow an unauthenticated, remote attacker to cause a DoS condition
(CVE-2015-3194).

  - A vulnerability in OpenSSL could allow an unauthenticated, remote attacker to cause a DoS condition
(CVE-2015-3195).

  - A vulnerability in OpenSSL could allow an unauthenticated, remote attacker to cause a DoS condition
(CVE-2015-3196).

  - A vulnerability in the anonymous Diffie-Hellman cipher suite in OpenSSL could allow an unauthenticated,
remote attacker to cause a denial of service (DoS) condition (CVE-2015-1794)." );
	script_tag( name: "solution", value: "Update to Release 11.5(1) or later" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151204-openssl" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!model = get_kb_item( "cisco/ip_phone/model" )){
	exit( 0 );
}
if(IsMatchRegexp( model, "^CP-88.." )){
	if(!version = get_kb_item( "cisco/ip_phone/version" )){
		exit( 0 );
	}
	version = eregmatch( pattern: "sip88xx\\.([0-9-]+)", string: version );
	if(version[1] && ( IsMatchRegexp( version[1], "^10-2-1" ) || IsMatchRegexp( version[1], "^10-2-2" ) )){
		report = report_fixed_ver( installed_version: version[1], fixed_version: "11-5-1" );
		security_message( port: 0, data: report );
	}
}
exit( 0 );

