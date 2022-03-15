if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1947.1" );
	script_cve_id( "CVE-2019-15890", "CVE-2020-10756", "CVE-2020-13754", "CVE-2020-14364", "CVE-2020-25707", "CVE-2020-25723", "CVE-2020-29129", "CVE-2020-29130", "CVE-2020-8608", "CVE-2021-20257", "CVE-2021-3419" );
	script_tag( name: "creation_date", value: "2021-06-11 02:15:39 +0000 (Fri, 11 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-20 11:15:00 +0000 (Fri, 20 Sep 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1947-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1947-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211947-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2021:1947-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qemu fixes the following issues:

Fix OOB access during mmio operations (CVE-2020-13754, bsc#1172382)

Fix out-of-bounds read information disclosure in icmp6_send_echoreply
 (CVE-2020-10756, bsc#1172380)

For the record, these issues are fixed in this package already. Most are
 alternate references to previously mentioned issues: (CVE-2019-15890,
 bsc#1149813, CVE-2020-8608, bsc#1163019, CVE-2020-14364, bsc#1175534,
 CVE-2020-25707, bsc#1178683, CVE-2020-25723, bsc#1178935,
 CVE-2020-29130, bsc#1179477, CVE-2020-29129, bsc#1179484,
 CVE-2021-20257, bsc#1182846, CVE-2021-3419, bsc#1182975)" );
	script_tag( name: "affected", value: "'qemu' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "qemu", rpm: "qemu~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm", rpm: "qemu-arm~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm-debuginfo", rpm: "qemu-arm-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl", rpm: "qemu-block-curl~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl-debuginfo", rpm: "qemu-block-curl-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi", rpm: "qemu-block-iscsi~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi-debuginfo", rpm: "qemu-block-iscsi-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd", rpm: "qemu-block-rbd~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd-debuginfo", rpm: "qemu-block-rbd-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh", rpm: "qemu-block-ssh~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh-debuginfo", rpm: "qemu-block-ssh-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debugsource", rpm: "qemu-debugsource~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent-debuginfo", rpm: "qemu-guest-agent-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ipxe", rpm: "qemu-ipxe~1.0.0+~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-lang", rpm: "qemu-lang~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc", rpm: "qemu-ppc~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc-debuginfo", rpm: "qemu-ppc-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390", rpm: "qemu-s390~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390-debuginfo", rpm: "qemu-s390-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-seabios", rpm: "qemu-seabios~1.11.0_0_g63451fc~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-sgabios", rpm: "qemu-sgabios~8~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools", rpm: "qemu-tools~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools-debuginfo", rpm: "qemu-tools-debuginfo~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vgabios", rpm: "qemu-vgabios~1.11.0_0_g63451fc~5.32.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86", rpm: "qemu-x86~2.11.2~5.32.1", rls: "SLES12.0SP4" ) )){
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

