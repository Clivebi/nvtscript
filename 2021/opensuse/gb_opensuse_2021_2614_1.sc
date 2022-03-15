if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854035" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2020-25650", "CVE-2020-25651", "CVE-2020-25652", "CVE-2020-25653" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 17:38:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-08-07 03:01:31 +0000 (Sat, 07 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for spice-vdagent (openSUSE-SU-2021:2614-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2614-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UU4MAHRZUXACEK4PTFMFULLO5A7INQM5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-vdagent'
  package(s) announced via the openSUSE-SU-2021:2614-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for spice-vdagent fixes the following issues:

  - Update to version 0.21.0

  - CVE-2020-25650: memory DoS via arbitrary entries in `active_xfers` hash
       table (bsc#1177780)

  - CVE-2020-25651: possible file transfer DoS and information leak via
       `active_xfers` hash map (bsc#1177781)

  - CVE-2020-25652: possibility to exhaust file descriptors in `vdagentd`
       (bsc#1177782)

  - CVE-2020-25653: UNIX domain socket peer PID retrieved via `SO_PEERCRED`
       is subject to race condition (bsc#1177783)" );
	script_tag( name: "affected", value: "'spice-vdagent' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "spice-vdagent", rpm: "spice-vdagent~0.21.0~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-vdagent-debuginfo", rpm: "spice-vdagent-debuginfo~0.21.0~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-vdagent-debugsource", rpm: "spice-vdagent-debugsource~0.21.0~3.3.1", rls: "openSUSELeap15.3" ) )){
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

