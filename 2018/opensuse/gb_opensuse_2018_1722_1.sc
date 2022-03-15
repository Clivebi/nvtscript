if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852024" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_cve_id( "CVE-2018-12020" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:35:13 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for python-python-gnupg (openSUSE-SU-2018:1722-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:1722-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00033.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-python-gnupg'
  package(s) announced via the openSUSE-SU-2018:1722-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-python-gnupg to version 0.4.3 fixes the following
  issues:

  The following security vulnerabilities were addressed:

  - Sanitize diagnostic output of the original file name in verbose mode
  (CVE-2018-12020 boo#1096745)

  The following other changes were made:

  - Add --no-verbose to the gpg command line, in case verbose is specified
  is gpg.conf.

  - Add expect_passphrase password for use on GnuPG  = 2.1 when passing
  passphrase to gpg via pinentry

  - Provide a trust_keys method to allow setting the trust level for keys

  - When the gpg executable is not found, note the path used in the
  exception message

  - Make error messages more informational

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-646=1" );
	script_tag( name: "affected", value: "python-python-gnupg on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "python2-python-gnupg", rpm: "python2-python-gnupg~0.4.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-python-gnupg", rpm: "python3-python-gnupg~0.4.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

