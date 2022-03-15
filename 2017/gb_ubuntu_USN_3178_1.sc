if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843025" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-25 05:42:16 +0100 (Wed, 25 Jan 2017)" );
	script_cve_id( "CVE-2017-5208", "CVE-2017-5331", "CVE-2017-5332", "CVE-2017-5333" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-20 13:14:00 +0000 (Wed, 20 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for icoutils USN-3178-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icoutils'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that icoutils incorrectly handled memory when processing
certain files. If a user or automated system were tricked into opening a
specially crafted file, an attacker could cause icoutils to crash,
resulting in a denial of service, or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "icoutils on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3178-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3178-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icoutils", ver: "0.29.1-2ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

