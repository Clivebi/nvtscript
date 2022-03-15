if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844294" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2019-13627" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-01 13:25:00 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-01-15 04:00:31 +0000 (Wed, 15 Jan 2020)" );
	script_name( "Ubuntu Update for libgcrypt20 USN-4236-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4236-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005269.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgcrypt20'
  package(s) announced via the USN-4236-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4236-1 fixed a vulnerability in Libgcrypt. This update provides the
corresponding fix for Ubuntu 16.04 LTS.

Original advisory details:

It was discovered that Libgcrypt was susceptible to a ECDSA timing attack.
An attacker could possibly use this attack to recover sensitive
information." );
	script_tag( name: "affected", value: "'libgcrypt20' package(s) on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libgcrypt20", ver: "1.6.5-2ubuntu0.6", rls: "UBUNTU16.04 LTS" ) )){
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

