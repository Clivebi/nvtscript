CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105920" );
	script_version( "$Revision: 12095 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-07-31 13:20:03 +0200 (Thu, 31 Jul 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2013-5211" );
	script_bugtraq_id( 64692 );
	script_name( "Junos NTP Server Amplification Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version" );
	script_tag( name: "summary", value: "DoS in NTP server" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "When an NTP client or server is enabled within the [edit system
ntp] hierarchy level of the Junos configuration, REQ_MON_GETLIST and REQ_MON_GETLIST_1 control messages
supported by the monlist feature within NTP may allow remote attackers to cause a denial of service. NTP
is not enabled in Junos by default." );
	script_tag( name: "impact", value: "If NTP is enabled an attacker can exploit the control messages to use
it as part of a DoS attack against a remote victim or as the target of an attack against the device itself." );
	script_tag( name: "affected", value: "Junos OS 11.4, 12.1, 12.2, 12.3, 13.1, 13.2, 13.3" );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10613" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(revcomp( a: version, b: "11.4R12" ) < 0){
	security_message( port: 0, data: version );
	exit( 0 );
}
if(IsMatchRegexp( version, "^12" )){
	if( revcomp( a: version, b: "12.1R10" ) < 0 ){
		security_message( port: 0, data: version );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "12.1X44-D35" ) < 0 ) && ( revcomp( a: version, b: "12.1X44" ) >= 0 ) ){
			security_message( port: 0, data: version );
			exit( 0 );
		}
		else {
			if( ( revcomp( a: version, b: "12.1X45-D25" ) < 0 ) && ( revcomp( a: version, b: "12.1X45" ) >= 0 ) ){
				security_message( port: 0, data: version );
				exit( 0 );
			}
			else {
				if( ( revcomp( a: version, b: "12.1X46-D15" ) < 0 ) && ( revcomp( a: version, b: "12.1X46" ) >= 0 ) ){
					security_message( port: 0, data: version );
					exit( 0 );
				}
				else {
					if( ( revcomp( a: version, b: "12.1X47-D10" ) < 0 ) && ( revcomp( a: version, b: "12.1X47" ) >= 0 ) ){
						security_message( port: 0, data: version );
						exit( 0 );
					}
					else {
						if( ( revcomp( a: version, b: "12.2R8" ) < 0 ) && ( revcomp( a: version, b: "12.2" ) >= 0 ) ){
							security_message( port: 0, data: version );
							exit( 0 );
						}
						else {
							if(( revcomp( a: version, b: "12.3R7" ) < 0 ) && ( revcomp( a: version, b: "12.3" ) >= 0 )){
								security_message( port: 0, data: version );
								exit( 0 );
							}
						}
					}
				}
			}
		}
	}
}
if(IsMatchRegexp( version, "^13" )){
	if( revcomp( a: version, b: "13.1R4-S2" ) < 0 ){
		security_message( port: 0, data: version );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "13.2R4" ) < 0 ) && ( revcomp( a: version, b: "13.2" ) >= 0 ) ){
			security_message( port: 0, data: version );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "13.3R2" ) < 0 ) && ( revcomp( a: version, b: "13.3" ) >= 0 )){
				security_message( port: 0, data: version );
				exit( 0 );
			}
		}
	}
}

