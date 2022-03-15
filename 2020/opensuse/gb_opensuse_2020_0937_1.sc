if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853257" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-4067" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-08 03:03:51 +0000 (Wed, 08 Jul 2020)" );
	script_name( "openSUSE: Security Advisory for coturn (openSUSE-SU-2020:0937-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:0937-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00010.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'coturn'
  package(s) announced via the openSUSE-SU-2020:0937-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for coturn fixes the following issues:

  Version 4.5.1.3:

  * Remove reference to SSLv3: gh#coturn/coturn#566

  * Ignore MD5 for BoringSSL: gh#coturn/coturn#579

  * STUN response buffer not initialized properly, he issue found and
  reported gh#coturn/coturn#583 by Felix Dorre all credits belongs to
  him. CVE-2020-4067, boo#1173510

  - Let coturn allow binding to ports below 1024 per default


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-937=1" );
	script_tag( name: "affected", value: "'coturn' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "coturn", rpm: "coturn~4.5.1.3~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "coturn-debuginfo", rpm: "coturn-debuginfo~4.5.1.3~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "coturn-debugsource", rpm: "coturn-debugsource~4.5.1.3~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "coturn-devel", rpm: "coturn-devel~4.5.1.3~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "coturn-utils", rpm: "coturn-utils~4.5.1.3~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "coturn-utils-debuginfo", rpm: "coturn-utils-debuginfo~4.5.1.3~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

