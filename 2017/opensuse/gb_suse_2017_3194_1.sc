if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851655" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-04 18:48:14 +0530 (Mon, 04 Dec 2017)" );
	script_cve_id( "CVE-2017-15289", "CVE-2017-15597" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for xen (openSUSE-SU-2017:3194-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen to version 4.7.4 (bsc#1027519) fixes several issues.

  This new feature was added:

  - Support migration of HVM domains larger than 1 TB

  These security issues were fixed:

  - bsc#1068187: Failure to recognize errors in the Populate on Demand (PoD)
  code allowed for DoS (XSA-246)

  - bsc#1068191: Missing p2m error checking in PoD code allowed unprivileged
  guests to retain a writable mapping of freed memory leading to
  information leaks, privilege escalation or DoS (XSA-247).

  - CVE-2017-15289: The mode4and5 write functions allowed local OS guest
  privileged users to cause a denial of service (out-of-bounds write
  access and Qemu process crash) via vectors related to dst calculation
  (bsc#1063123)

  - CVE-2017-15597: A grant copy operation being done on a grant of a dying
  domain allowed a malicious guest administrator to corrupt hypervisor
  memory, allowing for DoS or potentially privilege escalation and
  information leaks (bsc#1061075).

  This non-security issue was fixed:

  - bsc#1055047: Fixed --initrd-inject option in virt-install

  This update was imported from the SUSE:SLE-12-SP2:Update update project." );
	script_tag( name: "affected", value: "xen on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:3194-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.7.4_02~11.21.1", rls: "openSUSELeap42.2" ) )){
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

