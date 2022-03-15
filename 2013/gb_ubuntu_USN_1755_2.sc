if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1755-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841352" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-08 10:23:20 +0530 (Fri, 08 Mar 2013)" );
	script_cve_id( "CVE-2013-0809", "CVE-2013-1493" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1755-2" );
	script_name( "Ubuntu Update for openjdk-7 USN-1755-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.10" );
	script_tag( name: "affected", value: "openjdk-7 on Ubuntu 12.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1755-1 fixed vulnerabilities in OpenJDK 6. This update provides the
  corresponding updates for OpenJDK 7.

  Original advisory details:

  It was discovered that OpenJDK did not properly validate certain types
  of images. A remote attacker could exploit this to cause OpenJDK to crash.
  (CVE-2013-0809)

  It was discovered that OpenJDK did not properly check return values when
  performing color conversion for images. If a user were tricked into
  opening a crafted image with OpenJDK, such as with the Java plugin, a
  remote attacker could cause OpenJDK to crash or execute arbitrary code
  outside of the Java sandbox with the privileges of the user invoking the
  program. (CVE-2013-1493)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-cacao", ver: "7u15-2.3.7-0ubuntu1~12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm", ver: "7u15-2.3.7-0ubuntu1~12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre", ver: "7u15-2.3.7-0ubuntu1~12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless", ver: "7u15-2.3.7-0ubuntu1~12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u15-2.3.7-0ubuntu1~12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero", ver: "7u15-2.3.7-0ubuntu1~12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

