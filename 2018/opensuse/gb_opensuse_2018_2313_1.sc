if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851852" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-14 05:56:31 +0200 (Tue, 14 Aug 2018)" );
	script_cve_id( "CVE-2018-14912" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-02 18:39:00 +0000 (Tue, 02 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for cgit (openSUSE-SU-2018:2313-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cgit'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cgit to version 1.2.1 fixes the following issues:

  The following security vulnerability was addressed:

  - CVE-2018-14912: Fixed a directory traversal vulnerability, when
  enable-http-clone=1 is not turned off (boo#1103799)

  The following other changes were made:

  - Update to upstream release 1.2.1:

  - syntax-highlighting: replace invalid unicode with '?'

  - ui-repolist: properly sort by age

  - ui-patch: fix crash when using path limit

  - Update bundled git to 2.11.1

  - Update to upstream release 1.0:

  * Add repo.homepage/gitweb.homepage setting and homepage tab.

  * Show reverse paths in title bar so that browser tab shows filename.

  * Allow redirects even when caching is turned on.

  * More gracefully deal with unparsable commits.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-864=1" );
	script_tag( name: "affected", value: "cgit on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2313-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00048.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "cgit", rpm: "cgit~1.2.1~13.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cgit-debuginfo", rpm: "cgit-debuginfo~1.2.1~13.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cgit-debugsource", rpm: "cgit-debugsource~1.2.1~13.3.1", rls: "openSUSELeap42.3" ) )){
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

