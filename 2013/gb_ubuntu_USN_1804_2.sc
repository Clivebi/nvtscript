if(description){
	script_tag( name: "affected", value: "icedtea-web on Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1804-1 fixed vulnerabilities in IcedTea-Web. This update introduced
  a regression with the Java Network Launching Protocol (JNLP) when fetching
  content over SSL under certain configurations, such as when using the
  community-supported IcedTead 7 browser plugin. This update fixes the
  problem.

  We apologize for the inconvenience.

  Original advisory details:

  Jiri Vanek discovered that IcedTea-Web would use the same classloader for
  applets from different domains. A remote attacker could exploit this to
  expose sensitive information or potentially manipulate applets from other
  domains. (CVE-2013-1926)

  It was discovered that IcedTea-Web did not properly verify JAR files and
  was susceptible to the GIFAR attack. If a user were tricked into opening a
  malicious website, a remote attacker could potentially exploit this to
  execute code under certain circumstances. (CVE-2013-1927)" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841407" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-04-25 10:49:59 +0530 (Thu, 25 Apr 2013)" );
	script_cve_id( "CVE-2013-1926", "CVE-2013-1927" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Ubuntu Update for icedtea-web USN-1804-2" );
	script_xref( name: "USN", value: "1804-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1804-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "icedtea-7-plugin", ver: "1.2.3-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-netx", ver: "1.2.3-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "icedtea-netx", ver: "1.2.3-0ubuntu0.11.10.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

