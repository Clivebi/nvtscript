if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843852" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2015-5297" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:14:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-12-12 07:47:47 +0100 (Wed, 12 Dec 2018)" );
	script_name( "Ubuntu Update for pixman USN-3843-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	script_xref( name: "USN", value: "3843-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3843-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pixman'
  package(s) announced via the USN-3843-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that pixman incorrectly handled the general_composite_rect
function. A remote attacker could use this issue to cause pixman to crash,
resulting in a denial of service, or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "pixman on Ubuntu 14.04 LTS." );
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
	if(( res = isdpkgvuln( pkg: "libpixman-1-0", ver: "0.30.2-2ubuntu1.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

