if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852109" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2018-14036" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-06 16:16:00 +0000 (Thu, 06 Sep 2018)" );
	script_tag( name: "creation_date", value: "2018-11-10 05:57:31 +0100 (Sat, 10 Nov 2018)" );
	script_name( "openSUSE: Security Advisory for accountsservice (openSUSE-SU-2018:3710-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:3710-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00014.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'accountsservice'
  package(s) announced via the openSUSE-SU-2018:3710-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for accountsservice fixes the following issues:

  This security issue was fixed:

  - CVE-2018-14036: Prevent directory traversal caused by an insufficient
  path check in user_change_icon_file_authorized_cb() (bsc#1099699)

  Thsese non-security issues were fixed:

  - Don't abort loading users when an /etc/shadow entry is missing.
  (bsc#1090003)

  - When user session type is wayland, act_user_is_logged_in can return TRUE
  if the user is logged in. (bsc#1095918)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1380=1" );
	script_tag( name: "affected", value: "accountsservice on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "accountsservice", rpm: "accountsservice~0.6.45~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-debuginfo", rpm: "accountsservice-debuginfo~0.6.45~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-debugsource", rpm: "accountsservice-debugsource~0.6.45~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-devel", rpm: "accountsservice-devel~0.6.45~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaccountsservice0", rpm: "libaccountsservice0~0.6.45~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaccountsservice0-debuginfo", rpm: "libaccountsservice0-debuginfo~0.6.45~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-AccountsService-1_0", rpm: "typelib-1_0-AccountsService-1_0~0.6.45~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-lang", rpm: "accountsservice-lang~0.6.45~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
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

