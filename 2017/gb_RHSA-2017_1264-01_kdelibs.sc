if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871817" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-23 07:02:41 +0200 (Tue, 23 May 2017)" );
	script_cve_id( "CVE-2017-8422" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for kdelibs RHSA-2017:1264-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kdelibs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The K Desktop Environment (KDE) is a
graphical desktop environment for the X Window System. The kdelibs packages include
core libraries for the K Desktop Environment.

Security Fix(es):

  * A privilege escalation flaw was found in the way kdelibs handled D-Bus
messages. A local user could potentially use this flaw to gain root
privileges by spoofing a callerID and leveraging a privileged helper
application. (CVE-2017-8422)

Red Hat would like to thank Sebastian Krahmer (SUSE) for reporting this
issue." );
	script_tag( name: "affected", value: "kdelibs on
  Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:1264-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-May/msg00030.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "kdelibs", rpm: "kdelibs~4.14.8~6.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdelibs-common", rpm: "kdelibs-common~4.14.8~6.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdelibs-debuginfo", rpm: "kdelibs-debuginfo~4.14.8~6.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdelibs-devel", rpm: "kdelibs-devel~4.14.8~6.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdelibs-ktexteditor", rpm: "kdelibs-ktexteditor~4.14.8~6.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

