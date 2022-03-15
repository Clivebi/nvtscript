if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851272" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-04-13 05:17:37 +0200 (Wed, 13 Apr 2016)" );
	script_cve_id( "CVE-2016-3068", "CVE-2016-3069", "CVE-2016-3630" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for mercurial (openSUSE-SU-2016:1016-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mercurial'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "mercurial was updated to fix three security issues.

  These security issues were fixed:

  - CVE-2016-3069: Arbitrary code execution when converting Git repos
  (bsc#973176).

  - CVE-2016-3068: Arbitrary code execution with Git subrepos (bsc#973177).

  - CVE-2016-3630: Remote code execution in binary delta decoding
  (bsc#973175)." );
	script_tag( name: "affected", value: "mercurial on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1016-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "mercurial", rpm: "mercurial~3.1.2~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mercurial-debuginfo", rpm: "mercurial-debuginfo~3.1.2~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mercurial-debugsource", rpm: "mercurial-debugsource~3.1.2~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mercurial-lang", rpm: "mercurial-lang~3.1.2~7.1", rls: "openSUSE13.2" ) )){
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

