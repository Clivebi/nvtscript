if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853210" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2019-20637", "CVE-2020-11653" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-16 16:15:00 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-17 03:00:49 +0000 (Wed, 17 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for varnish (openSUSE-SU-2020:0808-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0808-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00026.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'varnish'
  package(s) announced via the openSUSE-SU-2020:0808-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for varnish fixes the following issues:

  - CVE-2019-20637: Fixed an information leak when handling one client
  request and the next on the same connection (boo#1169040)

  - CVE-2020-11653: Fixed a performance loss due to an assertion failure and
  daemon restart when communicating with TLS termination proxy that uses
  PROXY version 2 (boo#1169039)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-808=1" );
	script_tag( name: "affected", value: "'varnish' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvarnishapi2", rpm: "libvarnishapi2~6.2.1~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvarnishapi2-debuginfo", rpm: "libvarnishapi2-debuginfo~6.2.1~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish", rpm: "varnish~6.2.1~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-debuginfo", rpm: "varnish-debuginfo~6.2.1~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-debugsource", rpm: "varnish-debugsource~6.2.1~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-devel", rpm: "varnish-devel~6.2.1~lp151.3.6.1", rls: "openSUSELeap15.1" ) )){
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

