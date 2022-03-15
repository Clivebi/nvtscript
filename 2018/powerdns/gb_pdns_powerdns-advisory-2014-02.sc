if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112377" );
	script_version( "2020-03-11T09:57:55+0000" );
	script_tag( name: "last_modification", value: "2020-03-11 09:57:55 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-09-12 17:43:21 +0200 (Wed, 12 Sep 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2014-8601" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PowerDNS Security Advisory 2014-02: PowerDNS Recursor 3.6.1 and earlier can be made to provide bad service" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "pdns_version.sc" );
	script_mandatory_keys( "powerdns/recursor/installed" );
	script_tag( name: "summary", value: "PowerDNS Recursor before 3.6.2 does not limit delegation chaining,
  which allows remote attackers to cause a denial of service (\"performance degradations\") via a large
  or infinite number of referrals, as demonstrated by resolving domains hosted by ezdns.it." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PowerDNS Recursor before version 3.6.2." );
	script_tag( name: "solution", value: "Update PowerDNS Recursor to version 3.6.2." );
	script_xref( name: "URL", value: "https://doc.powerdns.com/md/security/powerdns-advisory-2014-02/" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:powerdns:recursor";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
if(version_is_less( version: version, test_version: "3.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.2" );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

