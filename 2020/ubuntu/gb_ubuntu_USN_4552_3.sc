if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844687" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2019-16729" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-27 20:15:00 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-29 04:00:30 +0000 (Thu, 29 Oct 2020)" );
	script_name( "Ubuntu: Security Advisory for pam-python (USN-4552-3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4552-3" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-October/005731.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pam-python'
  package(s) announced via the USN-4552-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4552-1 and USN-4552-2 fixed a vulnerability in Pam-python. The update
introduced a regression which prevented PAM modules written in Python from
importing python modules from site-specific directories.

We apologize for the inconvenience.

Original advisory details:

Malte Kraus discovered that Pam-python mishandled certain environment variables.
A local attacker could potentially use this vulnerability to execute programs
as root." );
	script_tag( name: "affected", value: "'pam-python' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libpam-python", ver: "1.0.6-1.1+deb10u1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libpam-python", ver: "1.0.4-1.1+deb8u1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
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

