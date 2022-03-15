if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1206.1" );
	script_cve_id( "CVE-2015-3209", "CVE-2015-4164" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-09 15:14:00 +0000 (Wed, 09 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1206-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1206-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151206-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2015:1206-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Xen was updated to fix two security issues:
CVE-2015-3209: Heap overflow in qemu pcnet controller allowing guest to host escape. (XSA-135, bsc#932770)
CVE-2015-4164: DoS through iret hypercall handler. (XSA-136, bsc#932996)
Security Issues:
CVE-2015-4164 CVE-2015-3209" );
	script_tag( name: "affected", value: "'Xen' package(s) on SUSE Linux Enterprise Server 10 SP4." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-pdf", rpm: "xen-doc-pdf~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-ps", rpm: "xen-doc-ps~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-bigsmp", rpm: "xen-kmp-bigsmp~3.2.3_17040_46_2.6.16.60_0.132.3~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-debug", rpm: "xen-kmp-debug~3.2.3_17040_46_2.6.16.60_0.132.3~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~3.2.3_17040_46_2.6.16.60_0.132.3~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-kdump", rpm: "xen-kmp-kdump~3.2.3_17040_46_2.6.16.60_0.132.3~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-kdumppae", rpm: "xen-kmp-kdumppae~3.2.3_17040_46_2.6.16.60_0.132.3~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-smp", rpm: "xen-kmp-smp~3.2.3_17040_46_2.6.16.60_0.132.3~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-vmi", rpm: "xen-kmp-vmi~3.2.3_17040_46_2.6.16.60_0.132.3~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-vmipae", rpm: "xen-kmp-vmipae~3.2.3_17040_46_2.6.16.60_0.132.3~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-ioemu", rpm: "xen-tools-ioemu~3.2.3_17040_46~0.17.1", rls: "SLES10.0SP4" ) )){
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

