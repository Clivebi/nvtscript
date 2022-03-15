if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843571" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-29 05:46:02 +0200 (Fri, 29 Jun 2018)" );
	script_cve_id( "CVE-2017-10686", "CVE-2017-11111", "CVE-2017-14228", "CVE-2017-17810", "CVE-2017-17811", "CVE-2017-17812", "CVE-2017-17813", "CVE-2017-17814", "CVE-2017-17815", "CVE-2017-17816", "CVE-2017-17817", "CVE-2017-17818", "CVE-2017-17819", "CVE-2017-17820", "CVE-2018-8881" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-28 05:29:00 +0000 (Thu, 28 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for nasm USN-3694-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nasm'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that NASM incorrectly handled certain source files. If a
user or automated system were tricked into processing a specially crafted
source file, a remote attacker could use these issues to cause NASM to
crash, resulting in a denial of service, or possibly execute arbitrary
code." );
	script_tag( name: "affected", value: "nasm on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3694-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3694-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "nasm", ver: "2.10.09-1ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

