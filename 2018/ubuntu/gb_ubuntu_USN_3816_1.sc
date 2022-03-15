if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843814" );
	script_version( "2021-08-02T02:00:56+0000" );
	script_cve_id( "CVE-2018-15686", "CVE-2018-15687", "CVE-2018-6954" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-02 02:00:56 +0000 (Mon, 02 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-28 16:33:00 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-11-13 06:00:33 +0100 (Tue, 13 Nov 2018)" );
	script_name( "Ubuntu Update for systemd USN-3816-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3816-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3816-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemd'
  package(s) announced via the USN-3816-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jann Horn discovered that unit_deserialize incorrectly handled status messages
above a certain length. A local attacker could potentially exploit this via
NotifyAccess to inject arbitrary state across re-execution and obtain root
privileges. (CVE-2018-15686)

Jann Horn discovered a race condition in chown_one(). A local attacker
could potentially exploit this by setting arbitrary permissions on certain
files to obtain root privileges. This issue only affected Ubuntu 18.04 LTS
and Ubuntu 18.10. (CVE-2018-15687)

It was discovered that systemd-tmpfiles mishandled symlinks in
non-terminal path components. A local attacker could potentially exploit
this by gaining ownership of certain files to obtain root privileges. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-6954)" );
	script_tag( name: "affected", value: "systemd on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "systemd", ver: "237-3ubuntu10.6", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "systemd", ver: "239-7ubuntu10.3", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "systemd", ver: "229-4ubuntu21.8", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

