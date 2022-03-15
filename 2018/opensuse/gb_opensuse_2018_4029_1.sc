if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852169" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2018-19516" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-18 13:17:00 +0000 (Wed, 18 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-12-10 07:38:46 +0100 (Mon, 10 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for messagelib (openSUSE-SU-2018:4029-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:4029-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00007.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'messagelib'
  package(s) announced via the openSUSE-SU-2018:4029-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for messagelib fixes the following issues:

  The following security vulnerability was addressed:

  - CVE-2018-19516: Fix a potential issue with opening messages in a new
  browser window when displaying mails as HTML (boo#1117958).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1508=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1508=1" );
	script_tag( name: "affected", value: "messagelib on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "messagelib", rpm: "messagelib~17.12.3~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "messagelib-debuginfo", rpm: "messagelib-debuginfo~17.12.3~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "messagelib-debugsource", rpm: "messagelib-debugsource~17.12.3~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "messagelib-devel", rpm: "messagelib-devel~17.12.3~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "messagelib-lang", rpm: "messagelib-lang~17.12.3~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

