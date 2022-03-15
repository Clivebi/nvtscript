if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850839" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)" );
	script_cve_id( "CVE-2015-0235" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for glibc (SUSE-SU-2015:0158-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for glibc fixes the following security issue:

  CVE-2015-0235: A vulnerability was found and fixed in the GNU C Library,
  specifically in the function gethostbyname(), that could lead to a local
  or remote buffer overflow. (bsc#913646)" );
	script_tag( name: "affected", value: "glibc on SUSE Linux Enterprise Server 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:0158-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES11\\.0SP3" );
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
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-html", rpm: "glibc-html~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-i18ndata", rpm: "glibc-i18ndata~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-info", rpm: "glibc-info~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale", rpm: "glibc-locale~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile", rpm: "glibc-profile~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-32bit", rpm: "glibc-32bit~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-32bit", rpm: "glibc-devel-32bit~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-32bit", rpm: "glibc-locale-32bit~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-32bit", rpm: "glibc-profile-32bit~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-x86", rpm: "glibc-locale-x86~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-x86", rpm: "glibc-profile-x86~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-x86", rpm: "glibc-x86~2.11.3~17.74.13", rls: "SLES11.0SP3" ) )){
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

