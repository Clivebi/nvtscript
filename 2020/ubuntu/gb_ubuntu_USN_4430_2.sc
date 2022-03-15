if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844509" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2020-10177", "CVE-2020-10378", "CVE-2020-10379", "CVE-2020-10994", "CVE-2020-11538" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 19:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-24 03:00:38 +0000 (Fri, 24 Jul 2020)" );
	script_name( "Ubuntu: Security Advisory for pillow (USN-4430-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.04 LTS" );
	script_xref( name: "USN", value: "4430-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005524.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pillow'
  package(s) announced via the USN-4430-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4430-1 fixed vulnerabilities in Pillow. This update provides the
corresponding updates for Ubuntu 20.04 LTS.

Original advisory details:

It was discovered that Pillow incorrectly handled certain image files. If
a user or automated system were tricked into opening a specially-crafted
image file, a remote attacker could possibly cause Pillow to crash,
resulting in a denial of service." );
	script_tag( name: "affected", value: "'pillow' package(s) on Ubuntu 20.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "python3-pil", ver: "7.0.0-4ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
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

