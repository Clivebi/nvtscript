if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852902" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2019-3688", "CVE-2019-3690" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-20 16:15:00 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:44:00 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for permissions (openSUSE-SU-2019:2672-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2672-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-12/msg00024.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'permissions'
  package(s) announced via the openSUSE-SU-2019:2672-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for permissions fixes the following issues:

  - CVE-2019-3688: Changed wrong ownership in /usr/sbin/pinger to root:squid
  which could have allowed a squid user to gain persistence by changing
  the binary (bsc#1093414).

  - CVE-2019-3690: Fixed a privilege escalation through untrusted symbolic
  links (bsc#1150734).

  - Fixed a regression which caused sagmentation fault (bsc#1157198).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2672=1" );
	script_tag( name: "affected", value: "'permissions' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "permissions", rpm: "permissions~20181116~lp151.4.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-debuginfo", rpm: "permissions-debuginfo~20181116~lp151.4.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-debugsource", rpm: "permissions-debugsource~20181116~lp151.4.9.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-zypp-plugin", rpm: "permissions-zypp-plugin~20181116~lp151.4.9.1", rls: "openSUSELeap15.1" ) )){
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

