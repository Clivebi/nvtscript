if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843562" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-15 05:47:56 +0200 (Fri, 15 Jun 2018)" );
	script_cve_id( "CVE-2018-12020" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for gnupg2 USN-3675-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnupg2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "insight", value: "USN-3675-1 fixed a vulnerability in GnuPG 2
for Ubuntu 18.04 LTS and Ubuntu 17.10. This update provides the corresponding
update for GnuPG 2 in Ubuntu 16.04 LTS and Ubuntu 14.04 LTS.

Original advisory details:

Marcus Brinkmann discovered that during decryption or verification,
GnuPG did not properly filter out terminal sequences when reporting the
original filename. An attacker could use this to specially craft a file
that would cause an application parsing GnuPG output to incorrectly
interpret the status of the cryptographic operation reported by GnuPG." );
	script_tag( name: "affected", value: "gnupg2 on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3675-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3675-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.22-3ubuntu1.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.1.11-6ubuntu2.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

