if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.14202.1" );
	script_cve_id( "CVE-2019-10218" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:14 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-29 13:15:00 +0000 (Sat, 29 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:14202-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:14202-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-201914202-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2019:14202-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for samba fixes the following issue:
CVE-2019-10218: Fixed a path injection caused by filenames containing
 path separators (bso#14071) (bsc#1144902)." );
	script_tag( name: "affected", value: "'samba' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "ldapsmb", rpm: "ldapsmb~1.34b~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1", rpm: "libldb1~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0", rpm: "libsmbclient0~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit", rpm: "libsmbclient0-32bit~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2", rpm: "libtalloc2~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-32bit", rpm: "libtalloc2-32bit~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1", rpm: "libtdb1~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-32bit", rpm: "libtdb1-32bit~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0", rpm: "libtevent0~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-32bit", rpm: "libtevent0-32bit~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0", rpm: "libwbclient0~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit", rpm: "libwbclient0-32bit~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-32bit", rpm: "samba-32bit~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit", rpm: "samba-client-32bit~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-krb-printing", rpm: "samba-krb-printing~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit", rpm: "samba-winbind-32bit~3.6.3~94.23.1", rls: "SLES11.0SP4" ) )){
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
