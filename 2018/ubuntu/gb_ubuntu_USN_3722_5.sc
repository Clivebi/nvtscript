if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843636" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-19 08:15:27 +0200 (Wed, 19 Sep 2018)" );
	script_cve_id( "CVE-2018-0360", "CVE-2018-0361" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 16:41:00 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for clamav USN-3722-5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "insight", value: "USN-3722-1 fixed vulnerabilities in ClamAV.
The new package introduced an issue which caused dpkg-reconfigure to enter an
infinite loop. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that ClamAV incorrectly handled parsing certain HWP
files. A remote attacker could use this issue to cause ClamAV to hang,
resulting in a denial of service. (CVE-2018-0360)
It was discovered that ClamAV incorrectly handled parsing certain PDF
files. A remote attacker could use this issue to cause ClamAV to hang,
resulting in a denial of service. (CVE-2018-0361)" );
	script_tag( name: "affected", value: "clamav on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3722-5" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3722-5/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.100.1+dfsg-1ubuntu0.14.04.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.100.1+dfsg-1ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.100.1+dfsg-1ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

