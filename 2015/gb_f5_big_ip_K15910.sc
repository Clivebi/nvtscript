CPE = "cpe:/h:f5:big-ip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105161" );
	script_bugtraq_id( 70883, 70766 );
	script_cve_id( "CVE-2014-3687", "CVE-2014-3673" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-05-05T11:50:38+0000" );
	script_name( "F5 BIG-IP - Linux kernel SCTP vulnerabilities CVE-2014-3673 and CVE-2014-3687" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K15910" );
	script_tag( name: "impact", value: "Remote attackers may be able to cause a denial-of-service (DoS) using malformed or duplicate ASCONF chunk." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2014-3673
The SCTP implementation in the Linux kernel through 3.17.2 allows remote attackers to cause a denial of service
(system crash) via a malformed ASCONF chunk, related to net/sctp/sm_make_chunk.c and net/sctp/sm_statefuns.c.

CVE-2014-3687
The sctp_assoc_lookup_asconf_ack function in net/sctp/associola.c in the SCTP implementation in the Linux kernel
through 3.17.2 allows remote attackers to cause a denial of service (panic) via duplicate ASCONF chunks that
trigger an incorrect uncork within the side-effect interpreter." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "F5 BIG-IP is prone to a remote denial-of-service vulnerability." );
	script_tag( name: "last_modification", value: "2021-05-05 11:50:38 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2015-01-09 14:08:36 +0100 (Fri, 09 Jan 2015)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "F5 Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_f5_big_ip_version.sc" );
	script_mandatory_keys( "f5/big_ip/version", "f5/big_ip/active_modules" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
require("list_array_func.inc.sc");
require("f5.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
check_f5["LTM"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "12.0.0;11.0.0;10.0.0-10.2.4;" );
check_f5["AAM"] = make_array( "affected", "11.4.0-11.6.0;", "unaffected", "12.0.0;" );
check_f5["AFM"] = make_array( "affected", "11.3.0-11.6.0;", "unaffected", "12.0.0;" );
check_f5["AVR"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "12.0.0;11.0.0;" );
check_f5["APM"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "12.0.0;11.0.0;10.1.0-10.2.4;" );
check_f5["ASM"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "12.0.0;11.0.0;10.0.0-10.2.4;" );
check_f5["GTM"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["LC"] = make_array( "affected", "11.1.0-11.6.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["PEM"] = make_array( "affected", "11.3.0-11.6.0;", "unaffected", "12.0.0;" );
check_f5["PSM"] = make_array( "affected", "11.1.0-11.4.1;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["WAM"] = make_array( "affected", "11.1.0-11.3.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
check_f5["WOM"] = make_array( "affected", "11.1.0-11.3.0;", "unaffected", "11.0.0;10.0.0-10.2.4;" );
if(report = f5_is_vulnerable( ca: check_f5, version: version )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

