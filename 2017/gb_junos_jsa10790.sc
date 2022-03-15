CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106944" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-13 12:08:53 +0700 (Thu, 13 Jul 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2017-2342" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos SRX Series: MACsec Failure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version", "Junos/model" );
	script_tag( name: "summary", value: "Junos OS on SRX300 series are prone to a MACsec failure to report errors." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "MACsec feature does not report errors when a secure link can not be
established. It falls back to an unencrypted link. This can happen when MACsec is configured on ports that are
not capable of MACsec or when a secure link can not be established. This can mislead customers into believing
that a link is secure." );
	script_tag( name: "affected", value: "Junos OS 15.1X49 on SRX300 Series." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10790" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
model = get_kb_item( "Junos/model" );
if(!model || ( !IsMatchRegexp( toupper( model ), "^SRX3.." ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(( revcomp( a: version, b: "15.1X49-D100" ) < 0 ) && ( revcomp( a: version, b: "15.1X49" ) >= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "15.1X49-D100" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

