if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852865" );
	script_version( "2021-08-13T12:00:53+0000" );
	script_cve_id( "CVE-2019-13173" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:38:42 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for nodejs10 (openSUSE-SU-2019:1846-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:1846-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00010.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs10'
  package(s) announced via the openSUSE-SU-2019:1846-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs10 to version 10.16.0 fixes the following issues:

  Security issue fixed:

  - CVE-2019-13173: Fixed a potential file overwrite via hardlink in
  fstream.DirWriter() (bsc#1140290).

  Non-security issue fixed:

  - Update to new upstream LTS version 10.16.0, including npm version 6.9.0
  and openssl version 1.1.1b (bsc#1134208).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1846=1" );
	script_tag( name: "affected", value: "'nodejs10' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs10", rpm: "nodejs10~10.16.0~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debuginfo", rpm: "nodejs10-debuginfo~10.16.0~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debugsource", rpm: "nodejs10-debugsource~10.16.0~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-devel", rpm: "nodejs10-devel~10.16.0~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm10", rpm: "npm10~10.16.0~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-docs", rpm: "nodejs10-docs~10.16.0~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
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

