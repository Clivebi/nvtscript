if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0229.1" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-06-25 15:16:31 +0000 (Fri, 25 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0229-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0229-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140229-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel update for SLE11 SP2' package(s) announced via the SUSE-SU-2014:0229-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 11 Service Pack 2 kernel was updated to fix a regression introduced by the last update.

Regression fix:
- scsi_dh_alua: Incorrect reference counting in the SCSI
 ALUA initialization code lead to system crashes on boot
 (bnc#858831).

As the update introducing the regression was marked security, this is also marked security even though this bug is not security relevant." );
	script_tag( name: "affected", value: "'kernel update for SLE11 SP2' package(s) on SLE 11, SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise High Availability Extension 11 SP2, SUSE Linux Enterprise Server 11 SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base", rpm: "kernel-ec2-base~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae", rpm: "kernel-pae~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base", rpm: "kernel-pae-base~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-devel", rpm: "kernel-pae-devel~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64", rpm: "kernel-ppc64~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-base", rpm: "kernel-ppc64-base~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-devel", rpm: "kernel-ppc64-devel~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace", rpm: "kernel-trace~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-base", rpm: "kernel-trace-base~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-devel", rpm: "kernel-trace-devel~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.0.101~0.7.17.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.1.6_04_3.0.101_0.7.17~0.5.16", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-pae", rpm: "xen-kmp-pae~4.1.6_04_3.0.101_0.7.17~0.5.16", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-trace", rpm: "xen-kmp-trace~4.1.6_04_3.0.101_0.7.17~0.5.16", rls: "SLES11.0SP2" ) )){
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

