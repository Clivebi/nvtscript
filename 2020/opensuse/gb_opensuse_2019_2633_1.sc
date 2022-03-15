if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852934" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2019-0816" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:46:39 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for cloud-init (openSUSE-SU-2019:2633-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2633-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-12/msg00018.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cloud-init'
  package(s) announced via the openSUSE-SU-2019:2633-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cloud-init to version 19.2 fixes the following issues:

  Security issue fixed:

  - CVE-2019-0816: Fixed the unnecessary extra ssh keys that were added to
  authorized_keys (bsc#1129124).

  Non-security issues fixed:

  - Short circuit the conditional for identifying the sysconfig renderer
  (bsc#1154092, bsc#1142988).

  - If /etc/resolv.conf is a symlink, break it. This will avoid netconfig
  from clobbering the changes cloud-init applied (bsc#1151488).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2633=1" );
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
	if(!isnull( res = isrpmvuln( pkg: "cloud-init", rpm: "cloud-init~19.2~lp151.2.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cloud-init-config-suse", rpm: "cloud-init-config-suse~19.2~lp151.2.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cloud-init-doc", rpm: "cloud-init-doc~19.2~lp151.2.9.1", rls: "openSUSELeap15.1" ) )){
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

