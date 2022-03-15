if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853518" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2020-24972" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-28 16:15:00 +0000 (Wed, 28 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-25 04:00:49 +0000 (Sun, 25 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for kleopatra (openSUSE-SU-2020:1723-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1723-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00053.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kleopatra'
  package(s) announced via the openSUSE-SU-2020:1723-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kleopatra fixes the following issues:

  - CVE-2020-24972: Add upstream patch to prevent potential arbitrary code
  execution (boo#1177932):


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1723=1" );
	script_tag( name: "affected", value: "'kleopatra' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "kleopatra-lang", rpm: "kleopatra-lang~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kleopatra", rpm: "kleopatra~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kleopatra-debuginfo", rpm: "kleopatra-debuginfo~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kleopatra-debugsource", rpm: "kleopatra-debugsource~18.12.3~lp151.2.4.1", rls: "openSUSELeap15.1" ) )){
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

