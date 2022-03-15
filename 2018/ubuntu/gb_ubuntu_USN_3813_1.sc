if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843812" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_cve_id( "CVE-2018-1000807", "CVE-2018-1000808" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-27 12:21:00 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-11-09 06:05:26 +0100 (Fri, 09 Nov 2018)" );
	script_name( "Ubuntu Update for pyopenssl USN-3813-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(16\\.04 LTS)" );
	script_xref( name: "USN", value: "3813-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3813-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pyopenssl'
  package(s) announced via the USN-3813-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present
on the target host." );
	script_tag( name: "insight", value: "It was discovered that pyOpenSSL incorrectly handled memory when handling
X509 objects. A remote attacker could use this issue to cause pyOpenSSL to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2018-1000807)

It was discovered that pyOpenSSL incorrectly handled memory when performing
operations on a PKCS #12 store. A remote attacker could possibly use this
issue to cause pyOpenSSL to consume resources, resulting in a denial of
service. (CVE-2018-1000808)" );
	script_tag( name: "affected", value: "pyopenssl on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-openssl", ver: "0.15.1-2ubuntu0.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-openssl", ver: "0.15.1-2ubuntu0.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

