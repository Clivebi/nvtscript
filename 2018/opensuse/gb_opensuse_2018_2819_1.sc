if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851903" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-25 08:19:53 +0200 (Tue, 25 Sep 2018)" );
	script_cve_id( "CVE-2018-11440", "CVE-2018-11577", "CVE-2018-11683", "CVE-2018-11684", "CVE-2018-11685", "CVE-2018-12085" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for liblouis (openSUSE-SU-2018:2819-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'liblouis'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for liblouis fixes the following issues:

  Security issues fixed:

  - CVE-2018-11440: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (bsc#1095189)

  - CVE-2018-11577: Fixed a segmentation fault in lou_logPrint in logging.c
  (bsc#1095945)

  - CVE-2018-11683: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (different vulnerability than
  CVE-2018-11440) (bsc#1095827)

  - CVE-2018-11684: Fixed stack-based buffer overflow in the function
  includeFile() in compileTranslationTable.c (bsc#1095826)

  - CVE-2018-11685: Fixed a stack-based buffer overflow in the function
  compileHyphenation() in compileTranslationTable.c (bsc#1095825)

  - CVE-2018-12085: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (different vulnerability than
  CVE-2018-11440) (bsc#1097103)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1039=1" );
	script_tag( name: "affected", value: "liblouis on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2819-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00067.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "liblouis-data", rpm: "liblouis-data~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblouis-debugsource", rpm: "liblouis-debugsource~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblouis-devel", rpm: "liblouis-devel~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblouis-doc", rpm: "liblouis-doc~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblouis-tools", rpm: "liblouis-tools~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblouis-tools-debuginfo", rpm: "liblouis-tools-debuginfo~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblouis9", rpm: "liblouis9~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblouis9-debuginfo", rpm: "liblouis9-debuginfo~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-louis", rpm: "python-louis~2.6.4~9.1", rls: "openSUSELeap42.3" ) )){
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

