if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120355" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:24:29 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-316)" );
	script_tag( name: "insight", value: "A buffer overflow flaw was found in the way the decode_icmp_msg() function in the ICMP-MIB implementation processed Internet Control Message Protocol (ICMP) message statistics reported in the /proc/net/snmp file. A remote attacker could send a message for each ICMP message type, which could potentially cause the snmpd service to crash when processing the /proc/net/snmp file. (CVE-2014-2284 )" );
	script_tag( name: "solution", value: "Run yum update net-snmp to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-316.html" );
	script_cve_id( "CVE-2014-2284" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "net-snmp", rpm: "net-snmp~5.5~49.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-libs", rpm: "net-snmp-libs~5.5~49.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-utils", rpm: "net-snmp-utils~5.5~49.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-perl", rpm: "net-snmp-perl~5.5~49.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-devel", rpm: "net-snmp-devel~5.5~49.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-debuginfo", rpm: "net-snmp-debuginfo~5.5~49.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "net-snmp-python", rpm: "net-snmp-python~5.5~49.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

