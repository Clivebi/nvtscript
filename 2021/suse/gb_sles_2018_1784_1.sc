if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1784.1" );
	script_cve_id( "CVE-2017-5715" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1784-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1784-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181784-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel modules packages' package(s) announced via the SUSE-SU-2018:1784-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following kernel modules were rebuild with 'retpoline' enablement to allow full mitigation of the Spectre Variant 2 (CVE-2017-5715, bsc#1068032)
OFED was adjusted to add an entry to control the loading/unloading of cxgb4 to /etc/sysconf/infiniband (bsc#926856)." );
	script_tag( name: "affected", value: "'kernel modules packages' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Real Time Extension 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "iscsitarget", rpm: "iscsitarget~1.4.20~0.43.2.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "iscsitarget-kmp-bigmem", rpm: "iscsitarget-kmp-bigmem~1.4.20_3.0.101_108.52~0.43.2.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "iscsitarget-kmp-default", rpm: "iscsitarget-kmp-default~1.4.20_3.0.101_108.52~0.43.2.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "iscsitarget-kmp-pae", rpm: "iscsitarget-kmp-pae~1.4.20_3.0.101_108.52~0.43.2.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "iscsitarget-kmp-ppc64", rpm: "iscsitarget-kmp-ppc64~1.4.20_3.0.101_108.52~0.43.2.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "iscsitarget-kmp-trace", rpm: "iscsitarget-kmp-trace~1.4.20_3.0.101_108.52~0.43.2.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "iscsitarget-kmp-xen", rpm: "iscsitarget-kmp-xen~1.4.20_3.0.101_108.52~0.43.2.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed", rpm: "ofed~1.5.4.1~22.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-doc", rpm: "ofed-doc~1.5.4.1~22.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-bigmem", rpm: "ofed-kmp-bigmem~1.5.4.1_3.0.101_108.52~22.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-default", rpm: "ofed-kmp-default~1.5.4.1_3.0.101_108.52~22.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-pae", rpm: "ofed-kmp-pae~1.5.4.1_3.0.101_108.52~22.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-ppc64", rpm: "ofed-kmp-ppc64~1.5.4.1_3.0.101_108.52~22.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ofed-kmp-trace", rpm: "ofed-kmp-trace~1.5.4.1_3.0.101_108.52~22.3.1", rls: "SLES11.0SP4" ) )){
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

