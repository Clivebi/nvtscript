if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0713.1" );
	script_cve_id( "CVE-2012-2372" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-08-23 02:05:00 +0000 (Tue, 23 Aug 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0713-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0713-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130713-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'OFED' package(s) announced via the SUSE-SU-2013:0713-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "rds-ping in the OFED stack could have triggered a kernel BUG, which could have caused a local denial of service attack. (CVE-2012-2372)

Security Issue reference:

 * CVE-2012-2372
>" );
	script_tag( name: "affected", value: "'OFED' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "ofed", rpm: "ofed~1.5.2~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed", rpm: "ofed~1.5.2~0.14.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-bigsmp", rpm: "ofed-cxgb3-NIC-kmp-bigsmp~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-debug", rpm: "ofed-cxgb3-NIC-kmp-debug~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-debug", rpm: "ofed-cxgb3-NIC-kmp-debug~1.5.2_2.6.16.60_0.99.38~0.14.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-default", rpm: "ofed-cxgb3-NIC-kmp-default~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-default", rpm: "ofed-cxgb3-NIC-kmp-default~1.5.2_2.6.16.60_0.99.38~0.14.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-kdump", rpm: "ofed-cxgb3-NIC-kmp-kdump~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-kdump", rpm: "ofed-cxgb3-NIC-kmp-kdump~1.5.2_2.6.16.60_0.99.38~0.14.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-kdumppae", rpm: "ofed-cxgb3-NIC-kmp-kdumppae~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-ppc64", rpm: "ofed-cxgb3-NIC-kmp-ppc64~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-smp", rpm: "ofed-cxgb3-NIC-kmp-smp~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-smp", rpm: "ofed-cxgb3-NIC-kmp-smp~1.5.2_2.6.16.60_0.99.38~0.14.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-vmi", rpm: "ofed-cxgb3-NIC-kmp-vmi~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-cxgb3-NIC-kmp-vmipae", rpm: "ofed-cxgb3-NIC-kmp-vmipae~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-doc", rpm: "ofed-doc~1.5.2~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-doc", rpm: "ofed-doc~1.5.2~0.14.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-bigsmp", rpm: "ofed-kmp-bigsmp~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-debug", rpm: "ofed-kmp-debug~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-debug", rpm: "ofed-kmp-debug~1.5.2_2.6.16.60_0.99.38~0.14.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-default", rpm: "ofed-kmp-default~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-default", rpm: "ofed-kmp-default~1.5.2_2.6.16.60_0.99.38~0.14.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-kdump", rpm: "ofed-kmp-kdump~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-kdump", rpm: "ofed-kmp-kdump~1.5.2_2.6.16.60_0.99.38~0.14.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-kdumppae", rpm: "ofed-kmp-kdumppae~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-ppc64", rpm: "ofed-kmp-ppc64~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-smp", rpm: "ofed-kmp-smp~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-smp", rpm: "ofed-kmp-smp~1.5.2_2.6.16.60_0.99.38~0.14.3", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-vmi", rpm: "ofed-kmp-vmi~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-vmipae", rpm: "ofed-kmp-vmipae~1.5.2_2.6.16.60_0.99.36~0.14.1", rls: "SLES10.0SP4" ) )){
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

