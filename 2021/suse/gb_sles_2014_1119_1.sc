if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1119.1" );
	script_cve_id( "CVE-2012-4412", "CVE-2013-4237", "CVE-2014-5119" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1119-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1119-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141119-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2014:1119-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This glibc update fixes a critical privilege escalation problem and the following security and non security issues:

 * bnc#892073: An off-by-one error leading to a heap-based buffer
 overflow was found in __gconv_translit_find(). An exploit that targets the problem is publicly available. (CVE-2014-5119)
 * bnc#772242: Replace scope handing with master state
 * bnc#779320: Fix buffer overflow in strcoll (CVE-2012-4412)
 * bnc#818630: Fall back to localhost if no nameserver defined
 * bnc#828235: Fix missing character in IBM-943 charset
 * bnc#828637: Fix use of alloca in gaih_inet
 * bnc#834594: Fix readdir_r with long file names (CVE-2013-4237)

Security Issues:

 * CVE-2014-5119
 * CVE-2013-4237
 * CVE-2012-4412" );
	script_tag( name: "affected", value: "'glibc' package(s) on SUSE Linux Enterprise Server 10 SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-32bit", rpm: "glibc-32bit~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-32bit", rpm: "glibc-devel-32bit~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-html", rpm: "glibc-html~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-i18ndata", rpm: "glibc-i18ndata~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-info", rpm: "glibc-info~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale", rpm: "glibc-locale~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-32bit", rpm: "glibc-locale-32bit~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile", rpm: "glibc-profile~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-32bit", rpm: "glibc-profile-32bit~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.4~31.111.1", rls: "SLES10.0SP4" ) )){
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

