if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0580.1" );
	script_cve_id( "CVE-2014-9114" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0580-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0580-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150580-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'util-linux' package(s) announced via the SUSE-SU-2015:0580-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "util-linux has been updated to fix one security issue:

 * CVE-2014-9114: command injection flaw in blkid (bnc#907434).

Additionally, these non-security issues have been fixed:

 * Fix possible script hang (bnc#888678)
 * Enable build of libmount / findmnt (bnc#900965)
 * Don't stop trying filesystem when mounting fails with EACCESS
 (bnc#918041)
 * Fix possible loop in findmnt (bsc#917164)
 * Recognize Unisys s-Par as hypervisor (FATE#318231)
 * Include the utmpdump.1 manpage (bsc#901549).

Security Issues:

 * CVE-2014-9114" );
	script_tag( name: "affected", value: "'util-linux' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libblkid1", rpm: "libblkid1~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libblkid1-32bit", rpm: "libblkid1-32bit~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libblkid1-x86", rpm: "libblkid1-x86~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1", rpm: "libuuid1~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1-32bit", rpm: "libuuid1-32bit~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1-x86", rpm: "libuuid1-x86~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux", rpm: "util-linux~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux-lang", rpm: "util-linux-lang~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uuid-runtime", rpm: "uuid-runtime~2.19.1~6.62.1", rls: "SLES11.0SP3" ) )){
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

