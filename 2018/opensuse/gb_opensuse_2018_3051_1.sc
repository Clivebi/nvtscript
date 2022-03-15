if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851928" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-07 08:24:56 +0200 (Sun, 07 Oct 2018)" );
	script_cve_id( "CVE-2017-16541", "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-12371", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12383", "CVE-2018-12385", "CVE-2018-16541", "CVE-2018-5156", "CVE-2018-5187", "CVE-2018-5188" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 15:50:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2018:3051-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for Mozilla Thunderbird to version 60.2.1 fixes multiple
  issues.

  Multiple security issues were fixed in the Mozilla platform as advised in
  MFSA 2018-25. In general, these flaws cannot be exploited through email in
  Thunderbird because scripting is disabled when reading mail, but are
  potentially risks in browser or browser-like contexts:

  - CVE-2018-12377: Use-after-free in refresh driver timers (bsc#1107343)

  - CVE-2018-12378: Use-after-free in IndexedDB (bsc#1107343)

  - CVE-2017-16541: Proxy bypass using automount and autofs (bsc#1066489)

  - CVE-2018-12376: Memory safety bugs fixed in Firefox 62 and Firefox ESR
  60.2 (bsc#1107343)

  - CVE-2018-12385: Crash in TransportSecurityInfo due to cached data
  (bsc#1109363)

  - CVE-2018-12383: Setting a master password did not delete unencrypted
  previously stored passwords (bsc#1107343)

  - CVE-2018-12359: Buffer overflow using computed size of canvas element
  (bsc#1098998)

  - CVE-2018-12360: Use-after-free when using focus() (bsc#1098998)

  - CVE-2018-12361: Integer overflow in SwizzleData (bsc#1098998)

  - CVE-2018-12362: Integer overflow in SSSE3 scaler (bsc#1098998)

  - CVE-2018-12363: Use-after-free when appending DOM nodes (bsc#1098998)

  - CVE-2018-12364: CSRF attacks through 307 redirects and NPAPI plugins
  (bsc#1098998)

  - CVE-2018-12365: Compromised IPC child process can list local filenames
  (bsc#1098998)

  - CVE-2018-12371: Integer overflow in Skia library during edge builder
  allocation (bsc#1098998)

  - CVE-2018-12366: Invalid data handling during QCMS transformations
  (bsc#1098998)

  - CVE-2018-12367: Timing attack mitigation of PerformanceNavigationTiming
  (bsc#1098998)

  - CVE-2018-5156: Media recorder segmentation fault when track type is
  changed during capture (bsc#1098998)

  - CVE-2018-5187: Memory safety bugs fixed in Firefox 61, Firefox ESR 60.1,
  and Thunderbird 60 (bsc#1098998)

  - CVE-2018-5188: Memory safety bugs fixed in Firefox 61, Firefox ESR 60.1,
  Firefox ESR 52.9, and Thunderbird 60 (bsc#1098998)

  Other bugs fixes:

  - Fix date display issues (bsc#1109379)

  - Fix start-up crash due to folder name with special characters
  (bsc#1107772)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1139=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1139=1" );
	script_tag( name: "affected", value: "MozillaThunderbird on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:3051-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00014.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird", rpm: "MozillaThunderbird~60.2.1~77.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-buildsymbols", rpm: "MozillaThunderbird-buildsymbols~60.2.1~77.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debuginfo", rpm: "MozillaThunderbird-debuginfo~60.2.1~77.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debugsource", rpm: "MozillaThunderbird-debugsource~60.2.1~77.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-common", rpm: "MozillaThunderbird-translations-common~60.2.1~77.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-other", rpm: "MozillaThunderbird-translations-other~60.2.1~77.2", rls: "openSUSELeap42.3" ) )){
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

