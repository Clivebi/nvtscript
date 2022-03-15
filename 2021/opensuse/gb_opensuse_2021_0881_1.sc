if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853861" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2021-30544", "CVE-2021-30545", "CVE-2021-30546", "CVE-2021-30547", "CVE-2021-30548", "CVE-2021-30549", "CVE-2021-30550", "CVE-2021-30551", "CVE-2021-30552", "CVE-2021-30553" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-18 03:15:00 +0000 (Sun, 18 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 03:01:35 +0000 (Thu, 17 Jun 2021)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2021:0881-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0881-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JKDHVVJH6V5YXSGWD7GDW62DQXQ22Y5E" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:0881-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium fixes the following issues:

     Chromium 91.0.4472.101 (boo#1187141)

  * CVE-2021-30544: Use after free in BFCache

  * CVE-2021-30545: Use after free in Extensions

  * CVE-2021-30546: Use after free in Autofill

  * CVE-2021-30547: Out of bounds write in ANGLE

  * CVE-2021-30548: Use after free in Loader

  * CVE-2021-30549: Use after free in Spell check

  * CVE-2021-30550: Use after free in Accessibility

  * CVE-2021-30551: Type Confusion in V8

  * CVE-2021-30552: Use after free in Extensions

  * CVE-2021-30553: Use after free in Network service

  * Various fixes from internal audits, fuzzing and other initiatives" );
	script_tag( name: "affected", value: "'chromium' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~91.0.4472.101~lp152.2.104.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~91.0.4472.101~lp152.2.104.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~91.0.4472.101~lp152.2.104.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~91.0.4472.101~lp152.2.104.1", rls: "openSUSELeap15.2" ) )){
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

