if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851765" );
	script_version( "2020-06-03T08:38:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "creation_date", value: "2018-05-26 05:45:12 +0200 (Sat, 26 May 2018)" );
	script_cve_id( "CVE-2014-8146", "CVE-2014-8147", "CVE-2016-6293", "CVE-2017-14952", "CVE-2017-15422", "CVE-2017-17484", "CVE-2017-7867", "CVE-2017-7868" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for icu (openSUSE-SU-2018:1422-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "icu was updated to fix two security issues.

  These security issues were fixed:

  - CVE-2014-8147: The resolveImplicitLevels function in common/ubidi.c in
  the Unicode Bidirectional Algorithm implementation in ICU4C in
  International Components for Unicode (ICU) used an integer data type
  that is inconsistent with a header file, which allowed remote attackers
  to cause a denial of service (incorrect malloc followed by invalid free)
  or possibly execute arbitrary code via crafted text (bsc#929629).

  - CVE-2014-8146: The resolveImplicitLevels function in common/ubidi.c in
  the Unicode Bidirectional Algorithm implementation in ICU4C in
  International Components for Unicode (ICU) did not properly track
  directionally isolated pieces of text, which allowed remote attackers to
  cause a denial of service (heap-based buffer overflow) or possibly
  execute arbitrary code via crafted text (bsc#929629).

  - CVE-2016-6293: The uloc_acceptLanguageFromHTTP function in
  common/uloc.cpp in International Components for Unicode (ICU) for C/C++
  did not ensure that there is a '\\0' character at the end of a certain
  temporary array, which allowed remote attackers to cause a denial of
  service (out-of-bounds read) or possibly have unspecified other impact
  via a call with a long httpAcceptLanguage argument (bsc#990636).

  - CVE-2017-7868: International Components for Unicode (ICU) for C/C++
  2017-02-13 has an out-of-bounds write caused by a heap-based buffer
  overflow related to the utf8TextAccess function in common/utext.cpp and
  the utext_moveIndex32* function (bsc#1034674)

  - CVE-2017-7867: International Components for Unicode (ICU) for C/C++
  2017-02-13 has an out-of-bounds write caused by a heap-based buffer
  overflow related to the utf8TextAccess function in common/utext.cpp and
  the utext_setNativeIndex* function (bsc#1034678)

  - CVE-2017-14952: Double free in i18n/zonemeta.cpp in International
  Components for Unicode (ICU) for C/C++ allowed remote attackers to
  execute arbitrary code via a crafted string, aka a 'redundant UVector
  entry clean up function call' issue (bnc#1067203)

  - CVE-2017-17484: The ucnv_UTF8FromUTF8 function in ucnv_u8.cpp in
  International Components for Unicode (ICU) for C/C++ mishandled
  ucnv_convertEx calls for UTF-8 to UTF-8 conversion, which allowed remote
  attackers to cause a denial of service (stack-based buffer overflow and
  application crash) or possibly have unspecified other impact via a
  crafted string, as demonstrated by ZNC  (bnc#1072193)

  - CVE-2017-15422: An integer overflow in icu during persian calendar date
  processing could ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "icu on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:1422-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-05/msg00103.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "icu", rpm: "icu~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icu-data", rpm: "icu-data~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icu-debuginfo", rpm: "icu-debuginfo~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icu-debugsource", rpm: "icu-debugsource~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libicu-devel", rpm: "libicu-devel~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libicu-doc", rpm: "libicu-doc~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libicu52_1", rpm: "libicu52_1~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libicu52_1-data", rpm: "libicu52_1-data~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libicu52_1-debuginfo", rpm: "libicu52_1-debuginfo~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libicu-devel-32bit", rpm: "libicu-devel-32bit~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libicu52_1-32bit", rpm: "libicu52_1-32bit~52.1~18.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libicu52_1-debuginfo-32bit", rpm: "libicu52_1-debuginfo-32bit~52.1~18.1", rls: "openSUSELeap42.3" ) )){
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

