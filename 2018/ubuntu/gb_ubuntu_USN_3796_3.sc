if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843713" );
	script_version( "2021-06-04T11:00:20+0000" );
	script_cve_id( "CVE-2018-1000805" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:10:11 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for paramiko USN-3796-3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.10" );
	script_xref( name: "USN", value: "3796-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3796-3/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'paramiko'
  package(s) announced via the USN-3796-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3796-1 fixed a vulnerability in Paramiko. This update provides the
corresponding update for Ubuntu 18.10.

Original advisory details:

Daniel Hoffman discovered that Paramiko incorrectly handled authentication
when being used as a server. A remote attacker could use this issue to
bypass authentication without any credentials." );
	script_tag( name: "affected", value: "paramiko on Ubuntu 18.10." );
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
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "python-paramiko", ver: "2.4.1-0ubuntu3.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-paramiko", ver: "2.4.1-0ubuntu3.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

