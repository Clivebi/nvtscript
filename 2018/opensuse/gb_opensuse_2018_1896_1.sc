if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851809" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-06 05:50:43 +0200 (Fri, 06 Jul 2018)" );
	script_cve_id( "CVE-2018-10857", "CVE-2018-10859" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for git-annex (openSUSE-SU-2018:1896-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'git-annex'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for git-annex to version 6.20180626 fixes the following issues:

  - CVE-2018-10857: Prevent file content disclosure by refusing to download
  content that cannot be verified with a hash, from encrypted special
  remotes and glacier (bsc#1098062).

  - CVE-2018-10859: Prevent local gpg encrypted file disclosure by refusing
  to download content that cannot be verified with a hash, from encrypted
  special remotes (bsc#1098364).

  This update brings many other bug fixes and new features.
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-697=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-697=1" );
	script_tag( name: "affected", value: "git-annex on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:1896-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-07/msg00002.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "git-annex", rpm: "git-annex~6.20180626~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "git-annex-bash-completion", rpm: "git-annex-bash-completion~6.20180626~8.1", rls: "openSUSELeap42.3" ) )){
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

