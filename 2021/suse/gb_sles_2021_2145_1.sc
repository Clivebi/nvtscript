if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2145.1" );
	script_cve_id( "CVE-2019-20387", "CVE-2021-3200" );
	script_tag( name: "creation_date", value: "2021-06-24 02:16:28 +0000 (Thu, 24 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-30 21:15:00 +0000 (Thu, 30 Jan 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2145-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2145-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212145-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsolv' package(s) announced via the SUSE-SU-2021:2145-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libsolv fixes the following issues:

Security issues fixed:

CVE-2019-20387: Fixed heap-buffer-overflow in repodata_schema2id
 (bsc#1161510)

CVE-2021-3200: testcase_read: error out if repos are added or the system
 is changed too late (bsc#1186229)

Other issues fixed:

backport support for blacklisted packages to support ptf packages and
 retracted patches

fix ruleinfo of complex dependencies returning the wrong origin

fix SOLVER_FLAG_FOCUS_BEST updateing packages without reason

fix add_complex_recommends() selecting conflicted packages in rare cases

fix potential segfault in resolve_jobrules

fix solv_zchunk decoding error if large chunks are used" );
	script_tag( name: "affected", value: "'libsolv' package(s) on SUSE Linux Enterprise Server 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libsolv-debugsource", rpm: "libsolv-debugsource~0.6.37~2.27.24.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-devel", rpm: "libsolv-devel~0.6.37~2.27.24.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-tools", rpm: "libsolv-tools~0.6.37~2.27.24.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-tools-debuginfo", rpm: "libsolv-tools-debuginfo~0.6.37~2.27.24.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp", rpm: "libzypp~16.21.4~27.75.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debuginfo", rpm: "libzypp-debuginfo~16.21.4~27.75.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debugsource", rpm: "libzypp-debugsource~16.21.4~27.75.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-devel", rpm: "libzypp-devel~16.21.4~27.75.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-solv", rpm: "perl-solv~0.6.37~2.27.24.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-solv-debuginfo", rpm: "perl-solv-debuginfo~0.6.37~2.27.24.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-solv", rpm: "python-solv~0.6.37~2.27.24.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-solv-debuginfo", rpm: "python-solv-debuginfo~0.6.37~2.27.24.1", rls: "SLES12.0SP2" ) )){
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

