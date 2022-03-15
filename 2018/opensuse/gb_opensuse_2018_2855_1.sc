if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851991" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_cve_id( "CVE-2018-0732", "CVE-2018-12115" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-08 12:15:00 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:30:04 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for nodejs8 (openSUSE-SU-2018:2855-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2855-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00075.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs8'
  package(s) announced via the openSUSE-SU-2018:2855-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs8 to version 8.11.4 fixes the following issues:

  Security issues fixed:

  - CVE-2018-12115: Fixed an out-of-bounds memory write in Buffer that could
  be used to write to memory outside of a Buffer's memory space buffer
  (bsc#1105019)

  - Upgrade to OpenSSL 1.0.2p, which fixed:

  - CVE-2018-0732: Client denial-of-service due to large DH parameter
  (bsc#1097158)

  - ECDSA key extraction via local side-channel

  Other changes made:

  - Recommend same major version npm package (bsc#1097748)

  - Fix parallel/test-tls-passphrase.js test to continue to function with
  older versions of OpenSSL library.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1047=1" );
	script_tag( name: "affected", value: "nodejs8 on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs8", rpm: "nodejs8~8.11.4~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs8-debuginfo", rpm: "nodejs8-debuginfo~8.11.4~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs8-debugsource", rpm: "nodejs8-debugsource~8.11.4~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs8-devel", rpm: "nodejs8-devel~8.11.4~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm8", rpm: "npm8~8.11.4~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs8-docs", rpm: "nodejs8-docs~8.11.4~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

