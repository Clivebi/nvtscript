if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120142" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:18:30 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-78)" );
	script_tag( name: "insight", value: "The rio_ioctl function in drivers/net/ethernet/dlink/dl2k.c in the Linux kernel before 3.3.7 does not restrict access to the SIOCSMIIREG command, which allows local users to write data to an Ethernet adapter via an ioctl call." );
	script_tag( name: "solution", value: "Run yum update kernel to update your system. You will need to reboot your system in order for the new kernel to be running." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-78.html" );
	script_cve_id( "CVE-2012-2313" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.2.18~1.26.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.2.18~1.26.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.2.18~1.26.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo-common-i686", rpm: "kernel-debuginfo-common-i686~3.2.18~1.26.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debuginfo", rpm: "kernel-debuginfo~3.2.18~1.26.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-debuginfo", rpm: "kernel-tools-debuginfo~3.2.18~1.26.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~3.2.18~1.26.6.amzn1", rls: "AMAZON" ) )){
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
