if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853087" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2020-8631", "CVE-2020-8632" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-21 11:15:00 +0000 (Fri, 21 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-03-30 03:00:36 +0000 (Mon, 30 Mar 2020)" );
	script_name( "openSUSE: Security Advisory for cloud-init (openSUSE-SU-2020:0400-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0400-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00042.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cloud-init'
  package(s) announced via the openSUSE-SU-2020:0400-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cloud-init fixes the following security issues:

  - CVE-2020-8631: Replaced the theoretically predictable deterministic RNG
  with the system RNG (bsc#1162937).

  - CVE-2020-8632: Increased the default random password length from 9 to 20
  (bsc#1162936).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-400=1" );
	script_tag( name: "affected", value: "'cloud-init' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "cloud-init", rpm: "cloud-init~19.4~lp151.2.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cloud-init-config-suse", rpm: "cloud-init-config-suse~19.4~lp151.2.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cloud-init-doc", rpm: "cloud-init-doc~19.4~lp151.2.15.1", rls: "openSUSELeap15.1" ) )){
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

