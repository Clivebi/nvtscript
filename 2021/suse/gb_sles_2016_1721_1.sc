if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.1721.1" );
	script_cve_id( "CVE-2016-1234", "CVE-2016-3075", "CVE-2016-3706", "CVE-2016-4429" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:1721-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:1721-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20161721-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2016:1721-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for glibc provides the following fixes:
- Increase DTV_SURPLUS limit. (bsc#968787)
- Do not copy d_name field of struct dirent. (CVE-2016-1234, bsc#969727)
- Fix memory leak in _nss_dns_gethostbyname4_r. (bsc#973010)
- Fix stack overflow in _nss_dns_getnetbyname_r. (CVE-2016-3075,
 bsc#973164)
- Fix malloc performance regression from SLE 11. (bsc#975930)
- Fix getaddrinfo stack overflow in hostent conversion. (CVE-2016-3706,
 bsc#980483)
- Do not use alloca in clntudp_call (CVE-2016-4429, bsc#980854)" );
	script_tag( name: "affected", value: "'glibc' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-32bit", rpm: "glibc-32bit~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debuginfo", rpm: "glibc-debuginfo~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debuginfo-32bit", rpm: "glibc-debuginfo-32bit~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debugsource", rpm: "glibc-debugsource~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-32bit", rpm: "glibc-devel-32bit~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-debuginfo", rpm: "glibc-devel-debuginfo~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-debuginfo-32bit", rpm: "glibc-devel-debuginfo-32bit~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-html", rpm: "glibc-html~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-i18ndata", rpm: "glibc-i18ndata~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-info", rpm: "glibc-info~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale", rpm: "glibc-locale~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-32bit", rpm: "glibc-locale-32bit~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-debuginfo", rpm: "glibc-locale-debuginfo~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-debuginfo-32bit", rpm: "glibc-locale-debuginfo-32bit~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile", rpm: "glibc-profile~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-32bit", rpm: "glibc-profile-32bit~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.19~22.16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd-debuginfo", rpm: "nscd-debuginfo~2.19~22.16.2", rls: "SLES12.0" ) )){
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

