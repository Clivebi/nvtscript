if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852168" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2018-19141", "CVE-2018-19143" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-12-10 07:38:41 +0100 (Mon, 10 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for otrs (openSUSE-SU-2018:4046-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:4046-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00017.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'otrs'
  package(s) announced via the openSUSE-SU-2018:4046-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for otrs fixes the following issues:

  Update to version 4.0.33.

  Security issues fixed:

  - CVE-2018-19141: Fixed privilege escalation, that an attacker who is
  logged into OTRS as an admin user cannot manipulate the URL to cause
  execution of JavaScript in the context of OTRS.

  - CVE-2018-19143: Fixed remote file deletion, that an attacker who is
  logged into OTRS as a user cannot manipulate the submission form to
  cause deletion of arbitrary files that the OTRS web server user has
  write access to.
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1503=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1503=1" );
	script_tag( name: "affected", value: "otrs on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "otrs", rpm: "otrs~4.0.33~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "otrs-doc", rpm: "otrs-doc~4.0.33~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "otrs-itsm", rpm: "otrs-itsm~4.0.33~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

