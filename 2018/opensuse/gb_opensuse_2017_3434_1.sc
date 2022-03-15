if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851671" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-12-25 07:51:12 +0100 (Mon, 25 Dec 2017)" );
	script_cve_id( "CVE-2017-7829", "CVE-2017-7846", "CVE-2017-7847", "CVE-2017-7848" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-07 12:35:00 +0000 (Tue, 07 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for Mozilla (openSUSE-SU-2017:3434-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Mozilla'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for Mozilla Thunderbird to version 52.5.2 fixes the following
  vulnerabilities:

  - CVE-2017-7846: JavaScript Execution via RSS in mailbox:// origin
  (bsc#1074043)

  - CVE-2017-7847: Local path string can be leaked from RSS feed
  (bsc#1074044)

  - CVE-2017-7848: RSS Feed vulnerable to new line Injection (bsc#1074045)

  - CVE-2017-7829: From address with encoded null character is cut off in
  message header display (bsc#1074046)" );
	script_tag( name: "affected", value: "Mozilla on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:3434-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2017-12/msg00092.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird", rpm: "MozillaThunderbird~52.5.2~41.24.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-buildsymbols", rpm: "MozillaThunderbird-buildsymbols~52.5.2~41.24.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debuginfo", rpm: "MozillaThunderbird-debuginfo~52.5.2~41.24.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debugsource", rpm: "MozillaThunderbird-debugsource~52.5.2~41.24.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-devel", rpm: "MozillaThunderbird-devel~52.5.2~41.24.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-common", rpm: "MozillaThunderbird-translations-common~52.5.2~41.24.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-other", rpm: "MozillaThunderbird-translations-other~52.5.2~41.24.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird", rpm: "MozillaThunderbird~52.5.2~53.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-buildsymbols", rpm: "MozillaThunderbird-buildsymbols~52.5.2~53.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debuginfo", rpm: "MozillaThunderbird-debuginfo~52.5.2~53.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debugsource", rpm: "MozillaThunderbird-debugsource~52.5.2~53.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-devel", rpm: "MozillaThunderbird-devel~52.5.2~53.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-common", rpm: "MozillaThunderbird-translations-common~52.5.2~53.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-other", rpm: "MozillaThunderbird-translations-other~52.5.2~53.1", rls: "openSUSELeap42.3" ) )){
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

