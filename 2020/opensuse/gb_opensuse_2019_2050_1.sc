if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852937" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2019-10751" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-02 18:15:00 +0000 (Mon, 02 Sep 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:46:41 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for httpie (openSUSE-SU-2019:2050-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2050-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00003.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'httpie'
  package(s) announced via the openSUSE-SU-2019:2050-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for httpie fixes the following issues:

  httpie was updated to version 1.0.3:

  * Fix CVE-2019-10751 (HTTPie is volnerable to Open Redirect that allows an
  attacker to write an arbitrary file with supplied filename and content
  to the current directory, by redirecting a request from HTTP to a
  crafted URL pointing to a server in his or hers control. (bsc#1148466)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2050=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2019-2050=1" );
	script_tag( name: "affected", value: "'httpie' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "python3-httpie", rpm: "python3-httpie~1.0.3~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
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

