if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1364.1" );
	script_cve_id( "CVE-2015-0247", "CVE-2015-1572" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:55:00 +0000 (Tue, 09 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1364-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1364-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151364-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'e2fsprogs' package(s) announced via the SUSE-SU-2015:1364-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two security issues were fixed in e2fsprogs:
CVE-2015-0247: Various heap overflows were fixed in e2fsprogs (fsck, dumpe2fs, e2image).
CVE-2015-1572: Fixed a potential buffer overflow in closefs(). (bsc#918346)
Additionally, badblocks was enhanced to work with very large partitions. (bsc#932539)
Security Issues:
CVE-2015-0247 CVE-2015-1572" );
	script_tag( name: "affected", value: "'e2fsprogs' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs", rpm: "e2fsprogs~1.41.9~2.10.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libblkid1", rpm: "libblkid1~2.19.1~6.62.7", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libblkid1-32bit", rpm: "libblkid1-32bit~2.19.1~6.62.7", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libblkid1-x86", rpm: "libblkid1-x86~2.19.1~6.62.7", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2", rpm: "libcom_err2~1.41.9~2.10.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-32bit", rpm: "libcom_err2-32bit~1.41.9~2.10.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-x86", rpm: "libcom_err2-x86~1.41.9~2.10.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2", rpm: "libext2fs2~1.41.9~2.10.11.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1", rpm: "libuuid1~2.19.1~6.62.7", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1-32bit", rpm: "libuuid1-32bit~2.19.1~6.62.7", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1-x86", rpm: "libuuid1-x86~2.19.1~6.62.7", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uuid-runtime", rpm: "uuid-runtime~2.19.1~6.62.7", rls: "SLES11.0SP3" ) )){
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

