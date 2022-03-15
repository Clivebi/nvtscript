CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106940" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-13 09:02:35 +0700 (Thu, 13 Jul 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2017-2346" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos MS-MPC or MS-MIC DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version", "Junos/model" );
	script_tag( name: "summary", value: "Junos OS is prone to a denial of service vulnerability when parsing large
fragmented traffic through an ALG." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "An MS-MPC or MS-MIC Service PIC may crash when large fragmented packets are
passed through an Application Layer Gateway (ALG). Repeated crashes of the Service PC can result in an extended
denial of service condition. The issue can be seen only if NAT or stateful-firewall rules are configured with
ALGs enabled." );
	script_tag( name: "impact", value: "An unauthenticated attacker may cause a denial of service condition." );
	script_tag( name: "affected", value: "Junos OS 14.1X55, 14.2, 15.1 and 16.1." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10794" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
model = get_kb_item( "Junos/model" );
if(!model || ( !IsMatchRegexp( toupper( model ), "MX[0-9]+" ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^14\\.1X55" )){
	if(( revcomp( a: version, b: "14.1X55-D35" ) < 0 ) && ( revcomp( a: version, b: "14.1X55-D30" ) >= 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "14.1X55-D35" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^14\\.2R" )){
	if(( revcomp( a: version, b: "14.2R7-S4" ) < 0 ) && ( revcomp( a: version, b: "14.2R7" ) >= 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "14.2R7-S4" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^15\\.1R" )){
	if(( revcomp( a: version, b: "15.1R5-S2" ) < 0 ) && ( revcomp( a: version, b: "15.1R5" ) < 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "15.1R5-S2" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^16\\.1R" )){
	if(( revcomp( a: version, b: "16.1R3-S2" ) < 0 ) && ( revcomp( a: version, b: "16.1R2" ) < 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "16.1R3-S2" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

