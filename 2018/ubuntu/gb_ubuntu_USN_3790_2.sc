if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843769" );
	script_version( "2021-06-04T11:00:20+0000" );
	script_cve_id( "CVE-2018-18074" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 20:30:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:17:22 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for requests USN-3790-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.10" );
	script_xref( name: "USN", value: "3790-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3790-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'requests'
  package(s) announced via the USN-3790-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3790-1 fixed vulnerabilities in Requests. This update provides
the corresponding update for Ubuntu 18.10

Original advisory details:

It was discovered that Requests incorrectly handled certain HTTP
headers. An attacker could possibly use this issue to access sensitive
information." );
	script_tag( name: "affected", value: "requests on Ubuntu 18.10." );
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
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "python-requests", ver: "2.18.4-2ubuntu0.18.10.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-requests", ver: "2.18.4-2ubuntu0.18.10.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

