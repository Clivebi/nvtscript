if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852144" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2018-19208" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-14 15:27:00 +0000 (Tue, 14 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-11-26 15:08:53 +0100 (Mon, 26 Nov 2018)" );
	script_name( "openSUSE: Security Advisory for libwpd (openSUSE-SU-2018:3842-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2018:3842-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00038.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libwpd'
  package(s) announced via the openSUSE-SU-2018:3842-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libwpd fixes the following issues:

  Security issue fixed:

  - CVE-2018-19208: Fixed illegal address access inside libwpd at function
  WP6ContentListener:defineTable (bsc#1115713).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1440=1" );
	script_tag( name: "affected", value: "libwpd on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libwpd-0_10-10", rpm: "libwpd-0_10-10~0.10.2~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-0_10-10-debuginfo", rpm: "libwpd-0_10-10-debuginfo~0.10.2~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-debugsource", rpm: "libwpd-debugsource~0.10.2~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-devel", rpm: "libwpd-devel~0.10.2~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-tools", rpm: "libwpd-tools~0.10.2~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-tools-debuginfo", rpm: "libwpd-tools-debuginfo~0.10.2~11.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-devel-doc", rpm: "libwpd-devel-doc~0.10.2~11.1", rls: "openSUSELeap42.3" ) )){
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

