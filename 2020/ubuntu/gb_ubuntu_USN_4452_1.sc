if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844525" );
	script_version( "2021-07-09T02:00:48+0000" );
	script_cve_id( "CVE-2020-15708" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 02:00:48 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-12 20:09:00 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-05 03:00:27 +0000 (Wed, 05 Aug 2020)" );
	script_name( "Ubuntu: Security Advisory for libvirt (USN-4452-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.04 LTS" );
	script_xref( name: "USN", value: "4452-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-August/005548.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the USN-4452-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Trent Shea discovered that the libvirt package set incorrect permissions on
the UNIX domain socket. A local attacker could use this issue to access
libvirt and escalate privileges." );
	script_tag( name: "affected", value: "'libvirt' package(s) on Ubuntu 20.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "6.0.0-0ubuntu8.3", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon-system", ver: "6.0.0-0ubuntu8.3", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libvirt0", ver: "6.0.0-0ubuntu8.3", rls: "UBUNTU20.04 LTS" ) )){
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

