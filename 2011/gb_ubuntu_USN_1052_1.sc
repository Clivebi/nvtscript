if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1052-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840575" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-31 15:15:14 +0100 (Mon, 31 Jan 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1052-1" );
	script_cve_id( "CVE-2010-4351" );
	script_name( "Ubuntu Update for openjdk-6, openjdk-6b18 vulnerability USN-1052-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(9\\.10|10\\.10|10\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1052-1" );
	script_tag( name: "affected", value: "openjdk-6, openjdk-6b18 vulnerability on Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the JNLP SecurityManager in IcedTea for Java
  OpenJDK in some instances failed to properly apply the intended
  scurity policy in its checkPermission method. This could allow an
  attacker execute code with privileges that should have been prevented.
  (CVE-2010-4351)" );
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
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea6-plugin", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-dbg", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jdk", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b20-1.9.4-0ubuntu1~9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea6-plugin", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-dbg", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jdk", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b20-1.9.4-0ubuntu1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea6-plugin", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-dbg", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jdk", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b20-1.9.4-0ubuntu1~10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

