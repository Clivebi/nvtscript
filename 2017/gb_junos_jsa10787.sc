CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106946" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-13 13:32:10 +0700 (Thu, 13 Jul 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2017-2341" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version", "Junos/model" );
	script_tag( name: "summary", value: "Junos OS is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "An insufficient authentication vulnerability on platforms where Junos OS
instances are run in a virtualized environment, may allow unprivileged users on the Junos OS instance to gain
access to the host operating environment, and thus escalate privileges." );
	script_tag( name: "affected", value: "This issue affects Junos OS 14.1X53, 15.1, 15.1X49, 16.1. Affected
platforms: QFX5110, QFX5200, QFX10002, QFX10008, QFX10016, EX4600 and NFX250, EX4600, vSRX, SRX1500, SRX4100,
SRX4200, ACX5000 series." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10787" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
model = get_kb_item( "Junos/model" );
if(!model || ( ( !IsMatchRegexp( toupper( model ), "^(V)?SRX" ) ) && ( !IsMatchRegexp( toupper( model ), "^QFX(5110|5200|10002|10008|10016)" ) ) && ( !IsMatchRegexp( toupper( model ), "^(ACX5000|EX4600|NFX250)" ) ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(( revcomp( a: version, b: "14.1X53-D40" ) < 0 ) && ( revcomp( a: version, b: "14.1X53" ) >= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "14.1X53-D40" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "15.1R5" ) < 0 ) && ( revcomp( a: version, b: "15.1R" ) >= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "15.1R5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "15.1X49-D70" ) < 0 ) && ( revcomp( a: version, b: "15.1X49" ) >= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "15.1X49-D70" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: version, b: "16.1R2" ) < 0 ) && ( revcomp( a: version, b: "16.1R" ) >= 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "16.1R2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

