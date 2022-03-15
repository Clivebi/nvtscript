if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843775" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2017-10790", "CVE-2018-6003" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-28 14:15:00 +0000 (Sun, 28 Jun 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:18:10 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for libtasn1-6 USN-3547-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3547-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3547-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtasn1-6'
  package(s) announced via the USN-3547-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Libtasn1 incorrectly handled certain files.
If a user were tricked into opening a crafted file, an attacker could
possibly use this to cause a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-10790)

It was discovered that Libtasn1 incorrectly handled certain inputs.
An attacker could possibly use this to cause Libtasn1 to hang,
resulting in a denial of service. This issue only affected Ubuntu 16.04
LTS and Ubuntu 17.10. (CVE-2018-6003)" );
	script_tag( name: "affected", value: "libtasn1-6 on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtasn1-6", ver: "3.4-3ubuntu0.6", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libtasn1-6", ver: "4.12-2.1ubuntu0.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtasn1-6", ver: "4.7-3ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

