if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853627" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2019-12420", "CVE-2020-1946" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:22 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for spamassassin (openSUSE-SU-2021:0551-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0551-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GXHYC7MWI2M6Y32ROZZBS5HOZOAF2HAN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spamassassin'
  package(s) announced via the openSUSE-SU-2021:0551-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for spamassassin fixes the following issues:

  - CVE-2019-12420: memory leak via crafted messages (bsc#1159133)

  - CVE-2020-1946: security update (bsc#1184221)

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'spamassassin' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "perl-Mail-SpamAssassin", rpm: "perl-Mail-SpamAssassin~3.4.5~lp152.10.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Mail-SpamAssassin-Plugin-iXhash2", rpm: "perl-Mail-SpamAssassin-Plugin-iXhash2~2.05~lp152.10.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spamassassin", rpm: "spamassassin~3.4.5~lp152.10.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spamassassin-debuginfo", rpm: "spamassassin-debuginfo~3.4.5~lp152.10.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spamassassin-debugsource", rpm: "spamassassin-debugsource~3.4.5~lp152.10.3.1", rls: "openSUSELeap15.2" ) )){
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

