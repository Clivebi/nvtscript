if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120071" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:16:48 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-115)" );
	script_tag( name: "insight", value: "A denial of service flaw was found in the way the dhcpd daemon handled zero-length client identifiers. A remote attacker could use this flaw to send a specially-crafted request to dhcpd, possibly causing it to enter an infinite loop and consume an excessive amount of CPU time. (CVE-2012-3571 )Two memory leak flaws were found in the dhcpd daemon. A remote attacker could use these flaws to cause dhcpd to exhaust all available memory by sending a large number of DHCP requests. (CVE-2012-3954 )" );
	script_tag( name: "solution", value: "Run yum update dhcp to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-115.html" );
	script_cve_id( "CVE-2012-3571", "CVE-2012-3954" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.1.1~31.P1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.1.1~31.P1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-debuginfo", rpm: "dhcp-debuginfo~4.1.1~31.P1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhclient", rpm: "dhclient~4.1.1~31.P1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.1.1~31.P1.17.amzn1", rls: "AMAZON" ) )){
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
