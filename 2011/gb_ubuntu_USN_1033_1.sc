if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1033-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840556" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-04 09:11:34 +0100 (Tue, 04 Jan 2011)" );
	script_xref( name: "USN", value: "1033-1" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3905" );
	script_name( "Ubuntu Update for eucalyptus vulnerability USN-1033-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1033-1" );
	script_tag( name: "affected", value: "eucalyptus vulnerability on Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Eucalyptus did not verify password resets from
  the Admin UI correctly. An unauthenticated remote attacker could issue
  password reset requests to gain admin privileges in the Eucalyptus
  environment." );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "eucalyptus-cc", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eucalyptus-cloud", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eucalyptus-common", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eucalyptus-gl", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eucalyptus-java-common", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eucalyptus-nc", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eucalyptus-sc", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eucalyptus-walrus", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "uec-component-listener", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eucalyptus-udeb", ver: "2.0+bzr1241-0ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

