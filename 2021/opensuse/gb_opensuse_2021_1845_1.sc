if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853947" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2021-26720", "CVE-2021-3468" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 21:27:00 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:04:55 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for avahi (openSUSE-SU-2021:1845-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1845-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YAJ7F7M4LLALLHLSQR7PD7HCTVHGAFMX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'avahi'
  package(s) announced via the openSUSE-SU-2021:1845-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for avahi fixes the following issues:

  - CVE-2021-3468: avoid infinite loop by handling  HUP event in client_work
       (bsc#1184521).

  - CVE-2021-26720: drop privileges when invoking avahi-daemon-check-dns.sh
       (bsc#1180827)

  - Update avahi-daemon-check-dns.sh from Debian. Our previous version
       relied on ifconfig, route, and init.d.

  - Add sudo to requires: used to drop privileges." );
	script_tag( name: "affected", value: "'avahi' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-avahi", rpm: "python-avahi~0.6.32~5.13.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-avahi-gtk", rpm: "python-avahi-gtk~0.6.32~5.13.1", rls: "openSUSELeap15.3" ) )){
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

