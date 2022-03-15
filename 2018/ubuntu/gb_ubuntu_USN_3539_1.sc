if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843774" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_cve_id( "CVE-2017-17784", "CVE-2017-17785", "CVE-2017-17786", "CVE-2017-17787", "CVE-2017-17788", "CVE-2017-17789" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 18:25:00 +0000 (Wed, 13 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:17:53 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for gimp USN-3539-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	script_xref( name: "USN", value: "3539-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3539-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gimp'
  package(s) announced via the USN-3539-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that GIMP incorrectly handled certain images. If a
user were tricked into opening a specially crafted image, an attacker
could possibly use this to execute arbitrary code. (CVE-2017-17784,
CVE-2017-17785, CVE-2017-17786, CVE-2017-17787, CVE-2017-17788,
CVE-2017-17789)" );
	script_tag( name: "affected", value: "gimp on Ubuntu 14.04 LTS." );
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
	if(( res = isdpkgvuln( pkg: "gimp", ver: "2.8.10-0ubuntu1.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgimp2.0", ver: "2.8.10-0ubuntu1.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

