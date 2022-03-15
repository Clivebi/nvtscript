if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1419-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840981" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-13 10:33:28 +0530 (Fri, 13 Apr 2012)" );
	script_cve_id( "CVE-2012-1906", "CVE-2012-1986", "CVE-2012-1987", "CVE-2012-1988", "CVE-2012-1989" );
	script_xref( name: "USN", value: "1419-1" );
	script_name( "Ubuntu Update for puppet USN-1419-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1419-1" );
	script_tag( name: "affected", value: "puppet on Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Puppet used a predictable filename when downloading Mac
  OS X package files. A local attacker could exploit this to overwrite arbitrary
  files. (CVE-2012-1906)

  It was discovered that Puppet incorrectly handled filebucket retrieval
  requests. A local attacker could exploit this to read arbitrary files.
  (CVE-2012-1986)

  It was discovered that Puppet incorrectly handled filebucket store requests. A
  local attacker could exploit this to perform a denial of service via resource
  exhaustion. (CVE-2012-1987)

  It was discovered that Puppet incorrectly handled filebucket requests. A local
  attacker could exploit this to execute arbitrary code via a crafted file path.
  (CVE-2012-1988)

  It was discovered that Puppet used a predictable filename for the Telnet
  connection log file. A local attacker could exploit this to overwrite arbitrary
  files. This issue only affected Ubuntu 11.10. (CVE-2012-1989)" );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "puppet-common", ver: "0.25.4-2ubuntu6.7", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.7.1-1ubuntu3.6", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.6.4-2ubuntu2.9", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

