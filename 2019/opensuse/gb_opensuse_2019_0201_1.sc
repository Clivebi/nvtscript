if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852299" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-5736" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 20:15:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-02-19 04:06:06 +0100 (Tue, 19 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for docker-runc (openSUSE-SU-2019:0201-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:0201-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00044.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'docker-runc'
  package(s) announced via the openSUSE-SU-2019:0201-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for docker-runc fixes the following issues:

  Security issue fixed:

  - CVE-2019-5736: Effectively copying /proc/self/exe during re-exec to
  avoid write attacks to the host runc binary, which could lead to a
  container breakout (bsc#1121967)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-201=1" );
	script_tag( name: "affected", value: "docker-runc on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "docker-runc", rpm: "docker-runc~1.0.0rc5+gitr3562_69663f0bd4b6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-debuginfo", rpm: "docker-runc-debuginfo~1.0.0rc5+gitr3562_69663f0bd4b6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-debugsource", rpm: "docker-runc-debugsource~1.0.0rc5+gitr3562_69663f0bd4b6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-kubic", rpm: "docker-runc-kubic~1.0.0rc5+gitr3562_69663f0bd4b6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-kubic-debuginfo", rpm: "docker-runc-kubic-debuginfo~1.0.0rc5+gitr3562_69663f0bd4b6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-kubic-debugsource", rpm: "docker-runc-kubic-debugsource~1.0.0rc5+gitr3562_69663f0bd4b6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-kubic-test", rpm: "docker-runc-kubic-test~1.0.0rc5+gitr3562_69663f0bd4b6~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc-test", rpm: "docker-runc-test~1.0.0rc5+gitr3562_69663f0bd4b6~8.1", rls: "openSUSELeap42.3" ) )){
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

