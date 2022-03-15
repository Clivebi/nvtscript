if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841572" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-03 10:20:21 +0530 (Thu, 03 Oct 2013)" );
	script_cve_id( "CVE-2013-1438", "CVE-2013-1439" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for libkdcraw USN-1978-1" );
	script_tag( name: "affected", value: "libkdcraw on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that libKDcraw incorrectly handled photo files. If a user
or automated system were tricked into processing a specially crafted photo
file, applications linked against libKDcraw could be made to crash,
resulting in a denial of service. (CVE-2013-1438, CVE-2013-1439)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1978-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1978-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libkdcraw'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "libkdcraw20", ver: "4:4.8.5-0ubuntu0.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
