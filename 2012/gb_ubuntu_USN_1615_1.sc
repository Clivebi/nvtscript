if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1615-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841197" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-26 09:44:22 +0530 (Fri, 26 Oct 2012)" );
	script_cve_id( "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150", "CVE-2012-2135" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_xref( name: "USN", value: "1615-1" );
	script_name( "Ubuntu Update for python3.2 USN-1615-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1615-1" );
	script_tag( name: "affected", value: "python3.2 on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Python distutils contained a race condition when
  creating the ~/.pypirc file. A local attacker could exploit this to obtain
  sensitive information. (CVE-2011-4944)

  It was discovered that SimpleXMLRPCServer did not properly validate its
  input when handling HTTP POST requests. A remote attacker could exploit
  this to cause a denial of service via excessive CPU utilization. This issue
  only affected Ubuntu 11.04 and 11.10. (CVE-2012-0845)

  It was discovered that Python was susceptible to hash algorithm attacks.
  An attacker could cause a denial of service under certain circumstances.
  This updates adds the '-R' command line option and honors setting the
  PYTHONHASHSEED environment variable to 'random' to salt str and datetime
  objects with an unpredictable value. This issue only affected Ubuntu 11.04
  and 11.10. (CVE-2012-1150)

  Serhiy Storchaka discovered that the UTF16 decoder in Python did not
  properly reset internal variables after error handling. An attacker could
  exploit this to cause a denial of service via memory corruption. This issue
  did not affect Ubuntu 12.10. (CVE-2012-2135)" );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python3.2", ver: "3.2.3-0ubuntu3.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3.2-minimal", ver: "3.2.3-0ubuntu3.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "python3.2", ver: "3.2.2-0ubuntu1.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3.2-minimal", ver: "3.2.2-0ubuntu1.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "python3.2", ver: "3.2-1ubuntu1.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3.2-minimal", ver: "3.2-1ubuntu1.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

