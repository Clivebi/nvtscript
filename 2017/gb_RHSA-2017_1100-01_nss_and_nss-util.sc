if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871803" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-21 06:38:16 +0200 (Fri, 21 Apr 2017)" );
	script_cve_id( "CVE-2017-5461" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for nss and nss-util RHSA-2017:1100-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss and nss-util'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set
  of libraries designed to support the cross-platform development of
  security-enabled client and server applications.

The nss-util packages provide utilities for use with the Network Security
Services (NSS) libraries.

The following packages have been upgraded to a newer upstream version: nss
(3.28.4), nss-util (3.28.4).

Security Fix(es):

  * An out-of-bounds write flaw was found in the way NSS performed certain
Base64-decoding operations. An attacker could use this flaw to create a
specially crafted certificate which, when parsed by NSS, could cause it to
crash or execute arbitrary code, using the permissions of the user running
an application compiled against the NSS library. (CVE-2017-5461)

Red Hat would like to thank the Mozilla project for reporting this issue.
Upstream acknowledges Ronald Crane as the original reporter." );
	script_tag( name: "affected", value: "nss and nss-util on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:1100-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-April/msg00042.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(7|6)" );
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
	if(( res = isrpmvuln( pkg: "nss", rpm: "nss~3.28.4~1.0.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-debuginfo", rpm: "nss-debuginfo~3.28.4~1.0.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.28.4~1.0.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-sysinit", rpm: "nss-sysinit~3.28.4~1.0.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.28.4~1.0.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-util", rpm: "nss-util~3.28.4~1.0.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-util-debuginfo", rpm: "nss-util-debuginfo~3.28.4~1.0.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-util-devel", rpm: "nss-util-devel~3.28.4~1.0.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "nss", rpm: "nss~3.28.4~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-debuginfo", rpm: "nss-debuginfo~3.28.4~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.28.4~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-sysinit", rpm: "nss-sysinit~3.28.4~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.28.4~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-util", rpm: "nss-util~3.28.4~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-util-debuginfo", rpm: "nss-util-debuginfo~3.28.4~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-util-devel", rpm: "nss-util-devel~3.28.4~1.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
